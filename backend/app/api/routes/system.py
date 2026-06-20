import os
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select, text

from app.core.config import settings
from app.core.database import async_session_factory
from app.core.version import APP_VERSION
from app.models.attack import AptGroup, AttackVersion, Tactic, Technique
from app.models.ioc import IOCIndicator, IOCSource

router = APIRouter(prefix="/system", tags=["System"])


class SelfTestCheck(BaseModel):
    name: str
    status: str
    message: str
    details: dict[str, Any] = {}


class SelfTestResult(BaseModel):
    status: str
    version: str
    checked_at: str
    duration_ms: int
    checks: list[SelfTestCheck]


def _check(name: str, ok: bool, message: str, details: dict[str, Any] | None = None) -> SelfTestCheck:
    return SelfTestCheck(
        name=name,
        status="ok" if ok else "error",
        message=message,
        details=details or {},
    )


def _api_key_check() -> SelfTestCheck:
    providers: dict[str, dict[str, Any]] = {
        "anthropic": {
            "configured": bool(settings.anthropic_api_key),
            "env_var": "ANTHROPIC_API_KEY",
            "category": "llm",
            "required_for": ["Claude AI analysis"],
        },
        "openai": {
            "configured": bool(settings.openai_api_key),
            "env_var": "OPENAI_API_KEY",
            "category": "llm",
            "required_for": ["OpenAI AI analysis"],
        },
        "gemini": {
            "configured": bool(settings.gemini_api_key),
            "env_var": "GEMINI_API_KEY",
            "category": "llm",
            "required_for": ["Gemini AI analysis"],
        },
        "minimax": {
            "configured": bool(settings.minimax_api_key),
            "env_var": "MINIMAX_API_KEY",
            "category": "llm",
            "required_for": ["MiniMax AI analysis"],
        },
        "local_llm_base_url": {
            "configured": bool(settings.local_llm_base_url),
            "env_var": "LOCAL_LLM_BASE_URL",
            "category": "llm",
            "required_for": ["local LLM analysis"],
        },
        "threatfox": {
            "configured": bool(settings.threatfox_auth_key),
            "env_var": "THREATFOX_AUTH_KEY",
            "category": "feed",
            "required_for": ["ThreatFox IOC sync", "ThreatFox IOC Investigation lookup"],
        },
        "otx": {
            "configured": bool(settings.otx_api_key),
            "env_var": "OTX_API_KEY",
            "category": "feed",
            "required_for": ["AlienVault OTX IOC sync", "OTX IOC Investigation pivots"],
        },
        "virustotal": {
            "configured": bool(settings.virustotal_api_key),
            "env_var": "VIRUSTOTAL_API_KEY",
            "category": "investigation",
            "required_for": ["VirusTotal IOC lookup", "VirusTotal IOC Investigation enrichment"],
        },
        "urlscan": {
            "configured": True,
            "api_key_configured": bool(settings.urlscan_api_key),
            "env_var": "URLSCAN_API_KEY",
            "category": "investigation",
            "auth_mode": "public lookup; API key optional for higher limits",
            "required_for": ["urlscan IOC Investigation URL/domain/IP activity pivots"],
        },
        "greynoise": {
            "configured": True,
            "api_key_configured": bool(settings.greynoise_api_key),
            "env_var": "GREYNOISE_API_KEY",
            "category": "investigation",
            "auth_mode": "community lookup; API key reserved for paid support",
            "required_for": ["GreyNoise Community IP classification"],
        },
        "abuseipdb": {
            "configured": bool(settings.abuseipdb_api_key),
            "env_var": "ABUSEIPDB_API_KEY",
            "category": "investigation",
            "required_for": ["AbuseIPDB abuse confidence and network-owner context"],
        },
        "shodan": {
            "configured": bool(settings.shodan_api_key),
            "env_var": "SHODAN_API_KEY",
            "category": "investigation",
            "required_for": ["Shodan host exposure, ports, hostnames, and vulnerability context"],
        },
        "censys": {
            "configured": bool(settings.censys_api_key),
            "env_var": "CENSYS_API_KEY",
            "optional_env_var": "CENSYS_ORG_ID",
            "category": "investigation",
            "required_for": ["Censys host, DNS, service, ASN, and certificate-name pivots"],
        },
        "opencti": {
            "configured": bool(settings.opencti_url and settings.opencti_token),
            "env_var": "OPENCTI_URL + OPENCTI_TOKEN",
            "category": "feed",
            "required_for": ["OpenCTI pull/push/bidirectional sync"],
        },
    }
    configured = [name for name, data in providers.items() if data["configured"]]
    missing_optional = [name for name, data in providers.items() if not data["configured"]]
    configured_by_category: dict[str, list[str]] = {}
    missing_by_category: dict[str, list[str]] = {}
    for name, data in providers.items():
        category = str(data.get("category") or "other")
        target = configured_by_category if data["configured"] else missing_by_category
        target.setdefault(category, []).append(name)
    return _check(
        "api_keys",
        True,
        f"API key configuration checked: {len(configured)} configured, {len(missing_optional)} missing optional.",
        {
            "configured": configured,
            "missing_optional": missing_optional,
            "configured_by_category": configured_by_category,
            "missing_by_category": missing_by_category,
            "providers": providers,
            "secrets_exposed": False,
        },
    )


@router.get("/selftest", response_model=SelfTestResult)
async def selftest() -> SelfTestResult:
    started = perf_counter()
    checks: list[SelfTestCheck] = []

    try:
        async with async_session_factory() as session:
            await session.execute(text("select 1"))
            checks.append(
                _check(
                    "database",
                    True,
                    "Database connection succeeded.",
                    {
                        "db_name": settings.db_name,
                        "db_host": settings.db_host,
                        "external_data_dir": os.environ.get("ADVERSARYGRAPH_DB_DIR", "./data/postgres"),
                        "layout": "persistent external Postgres data directory; public references and private/custom data are source-separated",
                    },
                )
            )

            versions = (await session.execute(select(AttackVersion))).scalars().all()
            version_map = {version.domain: version.version for version in versions if version.is_latest}
            expected_domains = settings.attck_domain_list
            missing_domains = [domain for domain in expected_domains if domain not in version_map]
            checks.append(
                _check(
                    "attack_versions",
                    not missing_domains,
                    "ATT&CK/ATLAS versions are present."
                    if not missing_domains
                    else f"Missing ingested domains: {', '.join(missing_domains)}.",
                    {"latest_versions": version_map, "expected_domains": expected_domains},
                )
            )

            domain_counts: dict[str, dict[str, int]] = {}
            for domain in expected_domains:
                row = await session.execute(
                    select(AttackVersion.id).where(
                        AttackVersion.domain == domain,
                        AttackVersion.is_latest.is_(True),
                    )
                )
                version_id = row.scalar_one_or_none()
                if not version_id:
                    domain_counts[domain] = {"tactics": 0, "techniques": 0, "groups": 0}
                    continue
                tactics = await session.scalar(select(func.count()).select_from(Tactic).where(Tactic.version_id == version_id))
                techniques = await session.scalar(select(func.count()).select_from(Technique).where(Technique.version_id == version_id))
                groups = await session.scalar(select(func.count()).select_from(AptGroup).where(AptGroup.version_id == version_id))
                domain_counts[domain] = {
                    "tactics": int(tactics or 0),
                    "techniques": int(techniques or 0),
                    "groups": int(groups or 0),
                }

            empty_domains = [
                domain for domain, counts in domain_counts.items()
                if counts["tactics"] == 0 or counts["techniques"] == 0
            ]
            checks.append(
                _check(
                    "attack_data",
                    not empty_domains,
                    "ATT&CK/ATLAS tactics and techniques are loaded."
                    if not empty_domains
                    else f"No tactics or techniques loaded for: {', '.join(empty_domains)}.",
                    {"domain_counts": domain_counts},
                )
            )

            source_rows = (await session.execute(select(IOCSource))).scalars().all()
            source_counts_raw = await session.execute(
                select(IOCIndicator.source_id, func.count(IOCIndicator.id)).group_by(IOCIndicator.source_id)
            )
            source_counts = {str(source_id): int(count or 0) for source_id, count in source_counts_raw.all()}
            sources = [
                {
                    "source_id": source.source_id,
                    "label": source.label,
                    "kind": source.kind,
                    "enabled": source.enabled,
                    "sync_status": source.sync_status,
                    "sync_error": source.sync_error,
                    "last_synced_at": source.last_synced_at.isoformat() if source.last_synced_at else None,
                    "indicator_count": source_counts.get(source.source_id, 0),
                }
                for source in sorted(source_rows, key=lambda item: item.label.lower())
            ]
            enabled_sources = [source for source in sources if source["enabled"]]
            degraded_sources = [
                source for source in enabled_sources
                if source["sync_status"] and source["sync_status"] not in {"ok", "active", "configured"}
            ]
            checks.append(
                _check(
                    "ioc_sync",
                    True,
                    f"IOC sources checked: {len(enabled_sources)} enabled, {sum(item['indicator_count'] for item in sources)} indicators stored.",
                    {
                        "auto_full_sync_on_startup": settings.auto_ioc_full_sync_on_startup,
                        "startup_sync_days": max(1, min(7, settings.auto_threatfox_sync_days)),
                        "enabled_sources": len(enabled_sources),
                        "degraded_sources": len(degraded_sources),
                        "sources": sources,
                    },
                )
            )
    except Exception as exc:
        checks.append(
            _check(
                "database",
                False,
                f"Database self-test failed: {type(exc).__name__}: {exc}",
            )
        )

    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        checks.append(_check("redis", True, "Redis connection succeeded."))
    except Exception as exc:
        checks.append(_check("redis", False, f"Redis self-test failed: {type(exc).__name__}: {exc}"))

    checks.append(_api_key_check())

    failed = [check for check in checks if check.status != "ok"]
    status = "ok" if not failed else "error"
    return SelfTestResult(
        status=status,
        version=APP_VERSION,
        checked_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=int((perf_counter() - started) * 1000),
        checks=checks,
    )
