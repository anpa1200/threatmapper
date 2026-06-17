from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class IntelSource(Base):
    """External or built-in source used for sector/activity intelligence."""

    __tablename__ = "intel_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(50), default="feed")
    url: Mapped[str] = mapped_column(String(500), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_status: Mapped[str] = mapped_column(String(50), default="never")
    sync_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ActorIntelObservation(Base):
    """Evidence-backed actor sector, region, technology, or activity observation."""

    __tablename__ = "actor_intel_observations"
    __table_args__ = (
        UniqueConstraint(
            "source_id",
            "actor_name",
            "observation_type",
            "value",
            "source_url",
            name="uq_actor_intel_observation",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(100), index=True)
    actor_attack_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    actor_name: Mapped[str] = mapped_column(String(255), index=True)
    observation_type: Mapped[str] = mapped_column(String(50), index=True)
    value: Mapped[str] = mapped_column(String(255), index=True)
    normalized_value: Mapped[str] = mapped_column(String(255), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    first_seen: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_seen: Mapped[date | None] = mapped_column(Date, nullable=True)
    source_url: Mapped[str] = mapped_column(String(700), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ClientProfile(Base):
    """Reusable client context for relevance scoring."""

    __tablename__ = "client_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    sector: Mapped[str] = mapped_column(String(120), index=True)
    region: Mapped[str] = mapped_column(String(120), default="")
    technologies: Mapped[list] = mapped_column(JSONB, default=list)
    crown_jewels: Mapped[list] = mapped_column(JSONB, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
