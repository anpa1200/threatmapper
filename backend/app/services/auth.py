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


async def current_user(
    x_auth_user: str | None = Header(default=None),
    x_auth_roles: str | None = Header(default=None),
) -> TeamUser:
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
