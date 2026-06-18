from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.models.attack import AptGroup, AptGroupTechnique, AttackVersion, Technique

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


@dataclass(frozen=True)
class IndicatorTarget:
    value: str
    type: str
    endpoint: str
    vt_url: str


def classify_indicator(value: str) -> IndicatorTarget:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Indicator is empty")

    if HASH_RE.match(cleaned):
        return IndicatorTarget(
            value=cleaned.lower(),
            type="hash",
            endpoint=f"/files/{cleaned.lower()}",
            vt_url=f"https://www.virustotal.com/gui/file/{cleaned.lower()}",
        )

    try:
        ipaddress.ip_address(cleaned)
        return IndicatorTarget(
            value=cleaned,
            type="ip",
            endpoint=f"/ip_addresses/{cleaned}",
            vt_url=f"https://www.virustotal.com/gui/ip-address/{cleaned}",
        )
    except ValueError:
        pass

    parsed = urlparse(cleaned)
    if parsed.scheme and parsed.netloc:
        url_id = base64.urlsafe_b64encode(cleaned.encode()).decode().rstrip("=")
        return IndicatorTarget(
            value=cleaned,
            type="url",
            endpoint=f"/urls/{url_id}",
            vt_url=f"https://www.virustotal.com/gui/url/{url_id}",
        )

    domain = cleaned.lower().strip("/")
    if "." in domain and "/" not in domain and " " not in domain:
        return IndicatorTarget(
            value=domain,
            type="domain",
            endpoint=f"/domains/{domain}",
            vt_url=f"https://www.virustotal.com/gui/domain/{domain}",
        )

    raise ValueError("Unsupported IOC type. Use an IP, domain, URL, MD5, SHA1, or SHA256.")


async def lookup_virustotal_ioc(
    session: AsyncSession,
    indicator: str,
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    if not settings.virustotal_api_key:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not configured")

    target = classify_indicator(indicator)
    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(base_url=VT_BASE_URL, headers=headers, timeout=25) as client:
        object_response = await _vt_get(client, target.endpoint)
        mitre_response: dict[str, Any] | None = None
        if target.type == "hash":
            try:
                mitre_response = await _vt_get(client, f"/files/{target.value}/behaviour_mitre_trees")
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in {400, 404}:
                    raise

    attributes = object_response.get("data", {}).get("attributes", {})
    context_text = _flatten_text([attributes, mitre_response or {}])
    technique_ids = sorted(set(_extract_attack_ids(mitre_response or {}) | _extract_attack_ids(attributes)))
    techniques = await _resolve_techniques(session, technique_ids, domain)
    actors = await _match_local_actors(session, attributes, mitre_response or {}, domain)

    return {
        "indicator": target.value,
        "type": target.type,
        "virustotal_url": target.vt_url,
        "permalink": attributes.get("permalink") or target.vt_url,
        "summary": _summary(attributes),
        "reputation": attributes.get("reputation", 0),
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "tags": _dedupe_str_list(attributes.get("tags", [])),
        "threat_names": _threat_names(attributes),
        "detections": _detections(attributes),
        "ttps": techniques,
        "actors": actors,
        "context": _context(attributes, mitre_response, context_text),
    }


async def _vt_get(client: httpx.AsyncClient, endpoint: str) -> dict[str, Any]:
    response = await client.get(endpoint)
    if response.status_code == 404:
        raise ValueError("Indicator was not found in VirusTotal.")
    if response.status_code == 401:
        raise RuntimeError("VirusTotal API key was rejected.")
    if response.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit exceeded.")
    response.raise_for_status()
    return response.json()


def _summary(attributes: dict[str, Any]) -> str:
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    if malicious or suspicious:
        return f"{malicious} engines marked malicious and {suspicious} suspicious; {harmless} harmless, {undetected} undetected."
    return f"No malicious detections in last analysis; {harmless} harmless, {undetected} undetected."


def _threat_names(attributes: dict[str, Any]) -> list[str]:
    names: list[str] = []
    classification = attributes.get("popular_threat_classification") or {}
    for key in ("suggested_threat_label",):
        if classification.get(key):
            names.append(str(classification[key]))
    for bucket in ("popular_threat_name", "popular_threat_category"):
        for item in classification.get(bucket) or []:
            value = item.get("value") if isinstance(item, dict) else item
            if value:
                names.append(str(value))
    for key in ("meaningful_name", "popular_threat_name"):
        if attributes.get(key):
            names.append(str(attributes[key]))
    return _dedupe_str_list(names)


def _detections(attributes: dict[str, Any], limit: int = 18) -> list[dict[str, str]]:
    results = attributes.get("last_analysis_results") or {}
    rows = []
    for engine, data in results.items():
        if not isinstance(data, dict):
            continue
        category = str(data.get("category") or "")
        result = str(data.get("result") or "")
        if category in {"malicious", "suspicious"} or result:
            rows.append({"engine": str(engine), "category": category, "result": result})
    rows.sort(key=lambda row: (row["category"] != "malicious", row["engine"].lower()))
    return rows[:limit]


def _extract_attack_ids(value: Any) -> set[str]:
    return {match.upper() for match in ATTACK_ID_RE.findall(_flatten_text(value))}


async def _resolve_techniques(session: AsyncSession, attack_ids: list[str], domain: str) -> list[dict[str, Any]]:
    if not attack_ids:
        return []
    try:
        version_id = await _latest_version_id(session, domain)
        if not version_id:
            return [{"attack_id": attack_id, "name": "", "tactics": [], "url": ""} for attack_id in attack_ids]
        rows = await session.execute(
            select(Technique)
            .options(selectinload(Technique.tactics))
            .where(Technique.version_id == version_id, Technique.attack_id.in_(attack_ids))
        )
        by_id = {tech.attack_id: tech for tech in rows.scalars().all()}
        resolved = []
        for attack_id in attack_ids:
            tech = by_id.get(attack_id)
            resolved.append({
                "attack_id": attack_id,
                "name": tech.name if tech else "",
                "tactics": [t.shortname for t in tech.tactics] if tech else [],
                "url": tech.url if tech else "",
            })
        return resolved
    except Exception:
        return [{"attack_id": attack_id, "name": "", "tactics": [], "url": ""} for attack_id in attack_ids]


async def _match_local_actors(
    session: AsyncSession,
    attributes: dict[str, Any],
    mitre_response: dict[str, Any],
    domain: str,
) -> list[dict[str, Any]]:
    names = _candidate_actor_terms(attributes, mitre_response)
    if not names:
        return []
    try:
        version_id = await _latest_version_id(session, domain)
        if not version_id:
            return []
        rows = await session.execute(
            select(AptGroup)
            .options(selectinload(AptGroup.technique_usages).selectinload(AptGroupTechnique.technique))
            .where(AptGroup.version_id == version_id)
        )
        matches = []
        lower_terms = {term.lower() for term in names if len(term) >= 3}
        for group in rows.scalars().all():
            aliases = [str(alias) for alias in (group.aliases or [])]
            actor_terms = {group.name.lower(), *(alias.lower() for alias in aliases)}
            matched = sorted(actor_terms & lower_terms)
            if matched:
                technique_ids = sorted({usage.technique.attack_id for usage in group.technique_usages if usage.technique})
                matches.append({
                    "attack_id": group.attack_id,
                    "name": group.name,
                    "aliases": aliases,
                    "matched_terms": matched,
                    "technique_ids": technique_ids,
                    "url": group.url,
                })
        return sorted(matches, key=lambda item: item["name"].lower())[:12]
    except Exception:
        return []


async def _latest_version_id(session: AsyncSession, domain: str) -> int | None:
    row = await session.execute(select(AttackVersion.id).where(AttackVersion.domain == domain, AttackVersion.is_latest.is_(True)))
    return row.scalar_one_or_none()


def _candidate_actor_terms(attributes: dict[str, Any], mitre_response: dict[str, Any]) -> set[str]:
    terms = set(_threat_names(attributes))
    for key in ("tags", "crowdsourced_yara_results", "crowdsourced_ids_results", "sigma_analysis_results"):
        value = attributes.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    terms.add(item)
                elif isinstance(item, dict):
                    for subkey in ("rule_name", "rule_category", "description", "source", "author"):
                        if item.get(subkey):
                            terms.add(str(item[subkey]))
    terms.update(ATTACK_ID_RE.sub(" ", _flatten_text(mitre_response)).split())
    clean = {term.strip(" _-:/()[]{}.,").strip() for term in terms}
    return {term for term in clean if len(term) >= 3 and not term.upper().startswith("T")}


def _context(attributes: dict[str, Any], mitre_response: dict[str, Any] | None, context_text: str) -> dict[str, Any]:
    return {
        "has_mitre_behavior": bool(mitre_response),
        "crowdsourced_yara_count": len(attributes.get("crowdsourced_yara_results") or []),
        "crowdsourced_ids_count": len(attributes.get("crowdsourced_ids_results") or []),
        "sigma_result_count": len(attributes.get("sigma_analysis_results") or []),
        "context_terms": _dedupe_str_list(context_text.split())[:40],
    }


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(_flatten_text(item) for pair in value.items() for item in pair)
    if isinstance(value, list):
        return " ".join(_flatten_text(item) for item in value)
    return str(value)


def _dedupe_str_list(values: list[Any]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        text = str(value).strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            output.append(text)
    return output
