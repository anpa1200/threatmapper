import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AssetSurfaceCase(Base):
    __tablename__ = "asset_surface_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), index=True)
    filename: Mapped[str] = mapped_column(String(500), default="")
    provider: Mapped[str] = mapped_column(String(30), default="baseline")
    model: Mapped[str] = mapped_column(String(100), default="")
    use_ai: Mapped[bool] = mapped_column(Boolean, default=False)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    high_or_critical_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
