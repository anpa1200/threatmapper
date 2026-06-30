from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.pipeline import AuditEvent
from app.models.auth import AuthSession, UserAccount
from app.services.auth import (
    ALL_PERMISSIONS,
    SESSION_COOKIE,
    TeamUser,
    admin,
    audit_event,
    authenticate_credentials,
    bootstrap_admin_if_configured,
    create_session,
    current_user,
    hash_password,
    hash_token,
    new_totp_secret,
    normalize_role,
    normalize_permissions,
    password_policy,
    revoke_session,
    revoke_user_sessions,
    user_count,
    validate_password_policy,
    verify_totp,
    ROLE_PERMISSIONS,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=1, max_length=500)
    mfa_code: str | None = Field(default=None, max_length=12)


class UserCreateBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=10, max_length=500)
    display_name: str = Field(default="", max_length=255)
    role: str = Field(default="viewer")
    permissions: list[str] = Field(default_factory=list)
    enabled: bool = True


class UserUpdateBody(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    role: str | None = None
    permissions: list[str] | None = None
    enabled: bool | None = None


class PasswordBody(BaseModel):
    password: str = Field(..., min_length=10, max_length=500)


class MfaVerifyBody(BaseModel):
    code: str = Field(..., min_length=6, max_length=12)


def user_out(user: UserAccount) -> dict:
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "permissions": user.permissions or [],
        "effective_permissions": sorted(ROLE_PERMISSIONS.get(user.role, set()) | set(user.permissions or [])),
        "auth_provider": user.auth_provider,
        "external_subject": user.external_subject,
        "mfa_enabled": user.mfa_enabled,
        "enabled": user.enabled,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max(15, settings.auth_session_minutes) * 60,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )


@router.get("/status")
async def status(db: AsyncSession = Depends(get_session)):
    count = await user_count(db)
    return {
        "auth_enabled": settings.auth_enabled,
        "native_login_enabled": True,
        "sso_mode": settings.auth_sso_mode,
        "trusted_proxy_sso_enabled": bool(settings.proxy_secret),
        "user_count": count,
        "bootstrap_configured": bool(settings.auth_bootstrap_admin_password),
        "bootstrap_required": settings.auth_enabled and count == 0 and not settings.auth_bootstrap_admin_password,
        "roles": sorted(ROLE_PERMISSIONS.keys()),
        "permissions": sorted(ALL_PERMISSIONS),
        "role_permissions": {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()},
        "password_policy": password_policy(),
    }


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response, db: AsyncSession = Depends(get_session)):
    if await user_count(db) == 0:
        await bootstrap_admin_if_configured(db)
    try:
        user = await authenticate_credentials(db, body.username, body.password)
    except HTTPException:
        await audit_event(
            db,
            body.username.strip() or "unknown",
            "auth.login_failed",
            "user_account",
            details={
                "ip": request.client.host if request.client else "",
                "user_agent": request.headers.get("user-agent", "")[:500],
            },
        )
        await db.commit()
        raise
    if user.mfa_enabled and not verify_totp(user.mfa_secret, body.mfa_code or ""):
        await audit_event(db, user.username, "auth.mfa_failed", "user_account", str(user.id), {"ip": request.client.host if request.client else ""})
        await db.commit()
        raise HTTPException(401, "Invalid MFA code")
    token, session = await create_session(db, user, request)
    await audit_event(db, user.username, "auth.login", "auth_session", str(session.id), {"ip": session.ip_address, "mfa": user.mfa_enabled})
    await db.commit()
    await db.refresh(user)
    set_session_cookie(response, token)
    return {"token": token, "expires_at": session.expires_at, "user": user_out(user)}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_session)):
    authorization = request.headers.get("authorization", "")
    token = authorization.split(" ", 1)[1].strip() if authorization.lower().startswith("bearer ") else ""
    token = token or request.cookies.get(SESSION_COOKIE, "")
    session = await db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token))) if token else None
    await revoke_session(db, token)
    if session:
        user = await db.get(UserAccount, session.user_id)
        await audit_event(db, user.username if user else "unknown", "auth.logout", "auth_session", str(session.id))
        await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/me")
async def me(user: TeamUser = Depends(current_user)):
    return {
        "name": user.name,
        "roles": user.roles,
        "permissions": user.permissions or [],
        "auth_enabled": settings.auth_enabled,
        "user_id": user.user_id,
        "auth_source": user.auth_source,
    }


@router.get("/users")
async def list_users(db: AsyncSession = Depends(get_session), _: TeamUser = Depends(admin)):
    rows = await db.execute(select(UserAccount).order_by(UserAccount.created_at.asc()))
    return [user_out(row) for row in rows.scalars().all()]


@router.post("/users", status_code=201)
async def create_user(body: UserCreateBody, db: AsyncSession = Depends(get_session), _: TeamUser = Depends(admin)):
    role = normalize_role(body.role)
    permissions = normalize_permissions(body.permissions)
    validate_password_policy(body.password)
    existing = await db.scalar(select(UserAccount).where(UserAccount.username == body.username.strip()))
    if existing:
        raise HTTPException(409, "Username already exists")
    user = UserAccount(
        username=body.username.strip(),
        display_name=body.display_name.strip(),
        password_hash=hash_password(body.password),
        role=role,
        permissions=permissions,
        enabled=body.enabled,
    )
    db.add(user)
    await db.flush()
    await audit_event(db, _.name, "auth.user_create", "user_account", str(user.id), {"username": user.username, "role": user.role, "enabled": user.enabled})
    await db.commit()
    await db.refresh(user)
    return user_out(user)


@router.patch("/users/{user_id}")
async def update_user(user_id: UUID, body: UserUpdateBody, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        user.role = normalize_role(body.role)
    if body.permissions is not None:
        user.permissions = normalize_permissions(body.permissions)
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.enabled is not None:
        if not body.enabled and str(user.id) == current.user_id:
            raise HTTPException(400, "You cannot disable your own account")
        user.enabled = body.enabled
    await audit_event(db, current.name, "auth.user_update", "user_account", str(user.id), {"username": user.username, "role": user.role, "enabled": user.enabled})
    await db.commit()
    await db.refresh(user)
    return user_out(user)


@router.post("/users/{user_id}/password")
async def set_password(user_id: UUID, body: PasswordBody, db: AsyncSession = Depends(get_session), _: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    validate_password_policy(body.password)
    user.password_hash = hash_password(body.password)
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    for session in rows.scalars().all():
        session.revoked_at = revoked_at
    await audit_event(db, _.name, "auth.password_reset", "user_account", str(user.id), {"username": user.username, "revoked_sessions": True})
    await db.commit()
    return {"status": "ok"}


@router.delete("/users/{user_id}", status_code=204)
async def disable_user(user_id: UUID, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if str(user.id) == current.user_id:
        raise HTTPException(400, "You cannot disable your own account")
    user.enabled = False
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    for session in rows.scalars().all():
        session.revoked_at = revoked_at
    await audit_event(db, current.name, "auth.user_disable", "user_account", str(user.id), {"username": user.username})
    await db.commit()
    return Response(status_code=204)


@router.get("/sessions")
async def list_sessions(db: AsyncSession = Depends(get_session), current: TeamUser = Depends(admin)):
    rows = await db.execute(
        select(AuthSession)
        .order_by(AuthSession.created_at.desc())
        .limit(500)
    )
    now = datetime.now(timezone.utc)
    items = []
    for session in rows.scalars().all():
        user = await db.get(UserAccount, session.user_id)
        if not user:
            continue
        active = session.revoked_at is None and session.expires_at > now
        items.append({
            "id": str(session.id),
            "user_id": str(user.id),
            "username": user.username,
            "auth_provider": user.auth_provider,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "expires_at": session.expires_at,
            "revoked_at": session.revoked_at,
            "created_at": session.created_at,
            "active": active,
        })
    await audit_event(db, current.name, "auth.sessions_view", "auth_session", details={"count": len(items)})
    await db.commit()
    return items


@router.post("/sessions/revoke-all")
async def revoke_all_my_sessions(request: Request, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(current_user)):
    authorization = request.headers.get("authorization", "")
    token = authorization.split(" ", 1)[1].strip() if authorization.lower().startswith("bearer ") else request.cookies.get(SESSION_COOKIE, "")
    if not current.user_id:
        raise HTTPException(400, "Current user has no local session identity")
    revoked = await revoke_user_sessions(db, UUID(current.user_id), keep_token=token)
    await audit_event(db, current.name, "auth.sessions_revoke_own", "user_account", current.user_id, {"revoked": revoked})
    await db.commit()
    return {"status": "ok", "revoked": revoked}


@router.post("/users/{user_id}/sessions/revoke")
async def revoke_user_session_set(user_id: UUID, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    revoked = await revoke_user_sessions(db, user_id)
    await audit_event(db, current.name, "auth.sessions_revoke_user", "user_account", str(user_id), {"username": user.username, "revoked": revoked})
    await db.commit()
    return {"status": "ok", "revoked": revoked}


@router.post("/mfa/setup")
async def setup_mfa(db: AsyncSession = Depends(get_session), current: TeamUser = Depends(current_user)):
    if not current.user_id:
        raise HTTPException(400, "MFA setup requires a local user account")
    user = await db.get(UserAccount, UUID(current.user_id))
    if not user:
        raise HTTPException(404, "User not found")
    user.mfa_secret = new_totp_secret()
    user.mfa_enabled = False
    await audit_event(db, current.name, "auth.mfa_setup_start", "user_account", str(user.id))
    await db.commit()
    return {
        "secret": user.mfa_secret,
        "otpauth_url": f"otpauth://totp/AdversaryGraph:{user.username}?secret={user.mfa_secret}&issuer=AdversaryGraph",
    }


@router.post("/mfa/confirm")
async def confirm_mfa(body: MfaVerifyBody, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(current_user)):
    if not current.user_id:
        raise HTTPException(400, "MFA confirmation requires a local user account")
    user = await db.get(UserAccount, UUID(current.user_id))
    if not user or not user.mfa_secret:
        raise HTTPException(400, "MFA setup has not been started")
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(401, "Invalid MFA code")
    user.mfa_enabled = True
    await audit_event(db, current.name, "auth.mfa_enable", "user_account", str(user.id))
    await db.commit()
    return {"status": "ok", "mfa_enabled": True}


@router.post("/users/{user_id}/mfa/disable")
async def disable_user_mfa(user_id: UUID, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.mfa_enabled = False
    user.mfa_secret = ""
    await audit_event(db, current.name, "auth.mfa_disable", "user_account", str(user.id), {"username": user.username})
    await db.commit()
    return {"status": "ok", "mfa_enabled": False}


@router.get("/audit")
async def auth_audit_events(db: AsyncSession = Depends(get_session), _: TeamUser = Depends(admin)):
    rows = await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(500))
    return [
        {
            "id": str(row.id),
            "actor": row.actor,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "details": row.details,
            "created_at": row.created_at,
        }
        for row in rows.scalars().all()
        if row.action.startswith("auth.")
    ]
