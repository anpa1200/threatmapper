from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import base64
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.auth import AuthSession, UserAccount
from app.models.pipeline import AuditEvent

VALID_ROLES = {
    "viewer",
    "analyst",
    "admin",
    "security_admin",
    "threat_intel",
    "detection_engineer",
    "incident_responder",
    "auditor",
    "service_account",
}
SESSION_COOKIE = "ag_session"
PBKDF2_ITERATIONS = 260_000
ALL_PERMISSIONS = {
    "read",
    "run_analysis",
    "manage_intel",
    "manage_detections",
    "run_attack_simulation",
    "manage_feeds",
    "forward_siem",
    "upload_files",
    "export_data",
    "manage_users",
    "manage_auth",
    "view_audit",
}
ROLE_PERMISSIONS = {
    "viewer": {"read"},
    "auditor": {"read", "view_audit", "export_data"},
    "analyst": {"read", "run_analysis", "manage_intel", "upload_files", "export_data"},
    "threat_intel": {"read", "run_analysis", "manage_intel", "manage_feeds", "upload_files", "export_data"},
    "detection_engineer": {"read", "run_analysis", "manage_detections", "run_attack_simulation", "forward_siem", "export_data"},
    "incident_responder": {"read", "run_analysis", "manage_intel", "run_attack_simulation", "forward_siem", "upload_files", "export_data"},
    "service_account": {"read", "run_analysis", "manage_feeds", "forward_siem", "export_data"},
    "security_admin": {"read", "run_analysis", "manage_intel", "manage_detections", "run_attack_simulation", "manage_feeds", "forward_siem", "upload_files", "export_data", "manage_auth", "view_audit"},
    "admin": set(ALL_PERMISSIONS),
}


@dataclass
class TeamUser:
    name: str
    roles: list[str]
    user_id: str = ""
    auth_source: str = "local"
    permissions: list[str] | None = None


def normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized not in VALID_ROLES:
        raise HTTPException(422, f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")
    return normalized


def normalize_permissions(permissions: list[str] | None) -> list[str]:
    cleaned = sorted({item.strip() for item in permissions or [] if item and item.strip()})
    invalid = [item for item in cleaned if item not in ALL_PERMISSIONS]
    if invalid:
        raise HTTPException(422, f"Unknown permissions: {', '.join(invalid)}")
    return cleaned


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def roles_for(role: str) -> list[str]:
    role = normalize_role(role)
    if role == "admin":
        return ["admin", "analyst", "viewer"]
    if role == "security_admin":
        return ["security_admin", "analyst", "viewer"]
    if role in {"threat_intel", "detection_engineer", "incident_responder", "service_account"}:
        return [role, "analyst", "viewer"]
    if role == "auditor":
        return ["auditor", "viewer"]
    if role == "analyst":
        return ["analyst", "viewer"]
    return ["viewer"]


def permissions_for(role: str, extra_permissions: list[str] | None = None) -> list[str]:
    normalized = normalize_role(role)
    permissions = set(ROLE_PERMISSIONS.get(normalized, {"read"}))
    permissions.update(normalize_permissions(extra_permissions))
    return sorted(permissions)


def user_to_team_user(user: UserAccount, auth_source: str = "native") -> TeamUser:
    return TeamUser(
        name=user.username,
        roles=roles_for(user.role),
        user_id=str(user.id),
        auth_source=auth_source,
        permissions=permissions_for(user.role, user.permissions),
    )


def password_policy() -> dict:
    return {
        "min_length": settings.auth_password_min_length,
        "require_upper": settings.auth_password_require_upper,
        "require_lower": settings.auth_password_require_lower,
        "require_number": settings.auth_password_require_number,
        "require_special": settings.auth_password_require_special,
        "mfa_available": True,
        "mfa_required": settings.auth_mfa_enabled,
    }


def validate_password_policy(password: str) -> None:
    errors: list[str] = []
    if len(password) < settings.auth_password_min_length:
        errors.append(f"at least {settings.auth_password_min_length} characters")
    if settings.auth_password_require_upper and not any(ch.isupper() for ch in password):
        errors.append("one uppercase letter")
    if settings.auth_password_require_lower and not any(ch.islower() for ch in password):
        errors.append("one lowercase letter")
    if settings.auth_password_require_number and not any(ch.isdigit() for ch in password):
        errors.append("one number")
    if settings.auth_password_require_special and not any(not ch.isalnum() for ch in password):
        errors.append("one special character")
    if errors:
        raise HTTPException(422, f"Password must contain {', '.join(errors)}")


async def user_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(UserAccount)) or 0)


async def bootstrap_admin_if_configured(db: AsyncSession) -> bool:
    if not settings.auth_enabled or not settings.auth_bootstrap_admin_password:
        return False
    if await user_count(db) > 0:
        return False
    username = settings.auth_bootstrap_admin_username.strip() or "admin"
    db.add(UserAccount(
        username=username,
        display_name="Bootstrap Administrator",
        password_hash=hash_password(settings.auth_bootstrap_admin_password),
        role="admin",
        permissions=[],
        enabled=True,
    ))
    await db.commit()
    return True


async def authenticate_credentials(db: AsyncSession, username: str, password: str) -> UserAccount:
    row = await db.scalar(select(UserAccount).where(UserAccount.username == username.strip()))
    if not row or not row.enabled or not verify_password(password, row.password_hash):
        raise HTTPException(401, "Invalid username or password")
    row.last_login_at = datetime.now(timezone.utc)
    return row


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp(secret: str, counter: int, digits: int = 6) -> str:
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    if not secret or not code or not code.isdigit():
        return False
    counter = int(time.time() // 30)
    return any(hmac.compare_digest(_totp(secret, counter + shift), code.zfill(6)) for shift in range(-window, window + 1))


async def create_session(db: AsyncSession, user: UserAccount, request: Request) -> tuple[str, AuthSession]:
    token = new_session_token()
    session = AuthSession(
        user_id=user.id,
        token_hash=hash_token(token),
        user_agent=request.headers.get("user-agent", "")[:2000],
        ip_address=(request.client.host if request.client else "")[:120],
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=max(15, settings.auth_session_minutes)),
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return token, session


async def authenticate_token(db: AsyncSession, token: str) -> UserAccount | None:
    if not token:
        return None
    now = datetime.now(timezone.utc)
    session = await db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == hash_token(token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
    )
    if not session:
        return None
    user = await db.get(UserAccount, session.user_id)
    if not user or not user.enabled:
        return None
    return user


async def revoke_session(db: AsyncSession, token: str) -> None:
    if not token:
        return
    session = await db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if session and not session.revoked_at:
        session.revoked_at = datetime.now(timezone.utc)
        await db.commit()


async def revoke_user_sessions(db: AsyncSession, user_id: UUID, keep_token: str = "") -> int:
    keep_hash = hash_token(keep_token) if keep_token else ""
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    count = 0
    for session in rows.scalars().all():
        if keep_hash and session.token_hash == keep_hash:
            continue
        session.revoked_at = revoked_at
        count += 1
    await db.commit()
    return count


async def audit_event(
    db: AsyncSession,
    actor: str,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    db.add(AuditEvent(actor=actor, action=action, object_type=object_type, object_id=object_id, details=details or {}))


async def current_user(
    request: Request,
    db: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
    ag_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    x_auth_user: str | None = Header(default=None),
    x_auth_roles: str | None = Header(default=None),
    x_internal_proxy_secret: str | None = Header(default=None),
) -> TeamUser:
    # If a proxy_secret is configured, verify it via constant-time comparison
    # before trusting any X-Auth-* headers. Requests with wrong/missing secret
    # are treated as anonymous unless native bearer/cookie auth succeeds.
    if settings.proxy_secret:
        provided = x_internal_proxy_secret or ""
        if not hmac.compare_digest(provided, settings.proxy_secret):
            x_auth_user = None
            x_auth_roles = None

    if x_auth_user:
        roles = [role.strip() for role in (x_auth_roles or settings.auth_default_role).split(",") if role.strip()]
        primary_role = roles[0] if roles else settings.auth_default_role
        return TeamUser(
            name=x_auth_user,
            roles=roles_for(primary_role),
            auth_source=settings.auth_sso_mode,
            permissions=permissions_for(primary_role),
        )

    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    token = token or ag_session or ""
    user = await authenticate_token(db, token)
    if user:
        return user_to_team_user(user)

    if settings.auth_enabled:
        raise HTTPException(401, "Authentication required")
    return TeamUser(
        name="local",
        roles=roles_for(settings.auth_default_role),
        auth_source="local",
        permissions=permissions_for(settings.auth_default_role),
    )


def has_permission(user: TeamUser, permission: str) -> bool:
    permissions = set(user.permissions or [])
    return "admin" in user.roles or permission in permissions


def require_permission(permission: str):
    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and not has_permission(user, permission):
            raise HTTPException(403, f"Permission required: {permission}")
        return user
    return dependency


async def analyst(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not ({"admin", "analyst"}.intersection(user.roles) or has_permission(user, "run_analysis")):
        raise HTTPException(403, "Analyst role required")
    return user


async def admin(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not has_permission(user, "manage_auth"):
        raise HTTPException(403, "Auth administrator permission required")
    return user


async def audit(
    db: AsyncSession,
    user: TeamUser,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    await audit_event(db, user.name, action, object_type, object_id, details)
