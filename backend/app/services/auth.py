import hmac
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.pipeline import AuditEvent


@dataclass
class TeamUser:
    name: str
    roles: list[str]


# NOTE: The reverse proxy MUST strip any client-supplied X-Auth-User,
# X-Auth-Roles, and X-Internal-Proxy-Secret headers before forwarding
# requests to this service. Failure to do so allows clients to impersonate
# arbitrary users.
async def current_user(
    x_auth_user: str | None = Header(default=None),
    x_auth_roles: str | None = Header(default=None),
    x_internal_proxy_secret: str | None = Header(default=None),
) -> TeamUser:
    # If a proxy_secret is configured, verify it via constant-time comparison
    # before trusting any X-Auth-* headers. Requests with wrong/missing secret
    # are treated as anonymous (no user, default role only).
    if settings.proxy_secret:
        provided = x_internal_proxy_secret or ""
        if not hmac.compare_digest(provided, settings.proxy_secret):
            # Proxy secret mismatch — ignore header-supplied identity entirely
            x_auth_user = None
            x_auth_roles = None

    if settings.auth_enabled and not x_auth_user:
        raise HTTPException(401, "Authentication required. Configure an OIDC proxy to set X-Auth-User.")
    return TeamUser(
        name=x_auth_user or "local",
        roles=[role.strip() for role in (x_auth_roles or settings.auth_default_role).split(",") if role.strip()],
    )


async def analyst(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not {"admin", "analyst"}.intersection(user.roles):
        raise HTTPException(403, "Analyst role required")
    return user


async def audit(
    db: AsyncSession,
    user: TeamUser,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    db.add(AuditEvent(actor=user.name, action=action, object_type=object_type, object_id=object_id, details=details or {}))
