from __future__ import annotations

from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services.sector_intel import (
    RelevanceInput,
    list_regions,
    list_sectors,
    list_sources,
    list_technologies,
    rank_actor_relevance,
    sync_misp_galaxy,
)

router = APIRouter(prefix="/sector", tags=["Sector Intelligence"])


class IntelSourceOut(BaseModel):
    source_id: str
    label: str
    kind: str
    url: str
    enabled: bool
    last_synced_at: datetime | None
    sync_status: str
    sync_error: str

    model_config = {"from_attributes": True}


class SectorOut(BaseModel):
    id: str
    label: str
    actor_count: int


class RegionOut(BaseModel):
    id: str
    label: str
    actor_count: int


class TechnologyOut(BaseModel):
    id: str
    label: str


class EvidenceOut(BaseModel):
    type: str
    value: str
    source: str
    url: str
    confidence: int
    evidence: str


class RelevantTechniqueOut(BaseModel):
    attack_id: str
    name: str
    tactics: list[str]


class ActorRelevanceOut(BaseModel):
    actor_attack_id: str
    actor_name: str
    aliases: list[str]
    score: int
    relevance: str
    technique_count: int
    recent_campaign_count: int
    campaign_count: int
    last_activity: date | None
    reasons: list[str]
    evidence: list[EvidenceOut]
    techniques: list[RelevantTechniqueOut]


class SyncOut(BaseModel):
    source: str
    actors: int
    matched: int
    observations: int


@router.get("/sources", response_model=list[IntelSourceOut])
async def sources(session: AsyncSession = Depends(get_session)):
    return await list_sources(session)


@router.post("/sync/misp-galaxy", response_model=SyncOut)
async def sync_misp(session: AsyncSession = Depends(get_session)):
    try:
        return await sync_misp_galaxy(session)
    except Exception as exc:
        raise HTTPException(502, f"MISP Galaxy sync failed: {exc}") from exc


@router.get("/sectors", response_model=list[SectorOut])
async def sectors(session: AsyncSession = Depends(get_session)):
    return await list_sectors(session)


@router.get("/regions", response_model=list[RegionOut])
async def regions(session: AsyncSession = Depends(get_session)):
    return await list_regions(session)


@router.get("/technologies", response_model=list[TechnologyOut])
async def technologies():
    return await list_technologies()


@router.get("/relevance", response_model=list[ActorRelevanceOut])
async def relevance(
    sectors: list[str] = Query(default_factory=list, description="Client sectors, for example telecom or finance"),
    regions: list[str] = Query(default_factory=list, description="Optional client geographies, for example Israel or Middle East"),
    sector: str | None = Query(None, min_length=2, description="Legacy single-sector filter"),
    region: str | None = Query(None, description="Legacy single-region filter"),
    technologies: list[str] = Query(default_factory=list, description="Optional client technology/environment keywords"),
    days: int = Query(365, ge=30, le=1825, description="Recent activity window"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(25, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
):
    selected_sectors = sectors or ([sector] if sector else [])
    selected_regions = regions or ([region] if region else [])
    if not selected_sectors:
        raise HTTPException(422, "At least one sector is required")
    return await rank_actor_relevance(
        session,
        RelevanceInput(
            sectors=selected_sectors,
            regions=selected_regions,
            technologies=technologies,
            days=days,
            domain=domain,
            limit=limit,
        ),
    )
