from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class IOCSource(Base):
    """External source used to collect indicators of compromise."""

    __tablename__ = "ioc_sources"

    source_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    label: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(80))
    url: Mapped[str] = mapped_column(String(500), default="")
    enabled: Mapped[bool] = mapped_column(default=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_status: Mapped[str] = mapped_column(String(50), default="configured")
    sync_error: Mapped[str] = mapped_column(Text, default="")


class IOCIndicator(Base):
    """A source-backed IOC with freshness, confidence, and optional malware context."""

    __tablename__ = "ioc_indicators"
    __table_args__ = (UniqueConstraint("value", "indicator_type", "source_id", name="uq_ioc_value_type_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(Text, index=True)
    indicator_type: Mapped[str] = mapped_column(String(80), index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("ioc_sources.source_id", ondelete="CASCADE"))
    source_url: Mapped[str] = mapped_column(String(1000), default="")
    first_seen: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(50), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    tlp: Mapped[str] = mapped_column(String(30), default="clear")
    malware_family: Mapped[str] = mapped_column(String(255), default="")
    campaign: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    actor_links: Mapped[list["IOCActorLink"]] = relationship(back_populates="indicator")


class IOCActorLink(Base):
    """Evidence-backed relationship between an IOC and an ATT&CK actor/group."""

    __tablename__ = "ioc_actor_links"
    __table_args__ = (
        UniqueConstraint("indicator_id", "actor_attack_id", "source_id", name="uq_ioc_actor_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("ioc_indicators.id", ondelete="CASCADE"))
    actor_attack_id: Mapped[str] = mapped_column(String(40), index=True)
    actor_name: Mapped[str] = mapped_column(String(255), index=True)
    source_id: Mapped[str] = mapped_column(String(120), index=True)
    relationship_type: Mapped[str] = mapped_column(String(80), default="attributed-to")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    indicator: Mapped["IOCIndicator"] = relationship(back_populates="actor_links")
