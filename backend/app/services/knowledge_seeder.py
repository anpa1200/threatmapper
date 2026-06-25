"""
Seed knowledge_articles from the bundled data/knowledge directory.
Idempotent — uses ON CONFLICT DO NOTHING on external_id.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgeArticle

DATA_DIR = Path(__file__).parent.parent / "data" / "knowledge"


# ── helpers ──────────────────────────────────────────────────────────────────

def _first_heading(text: str) -> str:
    for line in text.splitlines():
        stripped = line.lstrip("#").strip()
        if stripped:
            return stripped
    return "Untitled"


def _first_paragraph(text: str, max_chars: int = 300) -> str:
    in_fence = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or line.startswith("#") or line.startswith("|") or not line.strip():
            continue
        return line.strip()[:max_chars]
    return ""


def _extract_cves(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text)))


def _extract_techniques(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))


def _parse_cve_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = json.loads(path.read_text())
        vulns = raw.get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0]["cve"]
        cve_id = cve["id"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "",
        )
        published = cve.get("published")
        pub_dt = None
        if published:
            try:
                pub_dt = datetime.fromisoformat(published.rstrip("Z")).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        # CVSS
        cvss_score: float | None = None
        severity = "unknown"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                d = metrics[0].get("cvssData", {})
                cvss_score = d.get("baseScore")
                severity = d.get("baseSeverity", "").lower() or "unknown"
                break

        # Products
        products: list[str] = []
        for aff in cve.get("affected", []):
            for item in aff.get("affectedData", []):
                p = item.get("product", "")
                if p and p not in products:
                    products.append(p)

        # Weaknesses
        weaknesses: list[str] = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                cwe = d.get("value", "")
                if cwe and cwe not in weaknesses:
                    weaknesses.append(cwe)

        # Build markdown body
        lines = [
            f"# {cve_id}",
            "",
            f"**Severity:** {severity.upper()}  |  **CVSS:** {cvss_score or 'N/A'}",
            "",
            "## Description",
            desc,
            "",
        ]
        if products:
            lines += ["## Affected Products", *[f"- {p}" for p in products], ""]
        if weaknesses:
            lines += ["## Weakness Types (CWE)", *[f"- {w}" for w in weaknesses], ""]

        refs = cve.get("references", [])
        if refs:
            lines += ["## References", *[f"- {r['url']}" for r in refs[:5]], ""]

        tags = [cve_id, severity] + products + weaknesses
        tags = list(dict.fromkeys(t for t in tags if t))

        return {
            "category": "cve",
            "external_id": f"cve_{cve_id}",
            "title": f"{cve_id} — {products[0] if products else 'NVIDIA'}",
            "summary": desc[:300],
            "body": "\n".join(lines),
            "tags": tags,
            "meta": {
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "products": products,
                "weaknesses": weaknesses,
            },
            "source_file": str(path.name),
            "published_at": pub_dt,
        }
    except Exception:
        return None


def _parse_ghsa_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = json.loads(path.read_text())
        ghsa_id = raw.get("ghsaId") or raw.get("id") or path.stem
        summary = raw.get("summary", "")
        description = raw.get("description", "")
        severity = (raw.get("severity") or "").lower()
        published = raw.get("publishedAt") or raw.get("updated_at")

        pub_dt = None
        if published:
            try:
                pub_dt = datetime.fromisoformat(published.rstrip("Z")).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        cves: list[str] = []
        for id_entry in raw.get("identifiers", []):
            if id_entry.get("type") == "CVE":
                cves.append(id_entry["value"])

        body_lines = [f"# {ghsa_id}", "", f"**Severity:** {severity.upper() or 'N/A'}", ""]
        if summary:
            body_lines += ["## Summary", summary, ""]
        if description:
            body_lines += ["## Description", description, ""]
        if cves:
            body_lines += ["## CVE IDs", *[f"- {c}" for c in cves], ""]

        tags = [ghsa_id] + cves
        if severity:
            tags.append(severity)

        return {
            "category": "psirt_analysis",
            "external_id": f"ghsa_{ghsa_id}",
            "title": f"{ghsa_id} — {summary[:80]}",
            "summary": summary[:300],
            "body": "\n".join(body_lines),
            "tags": list(dict.fromkeys(t for t in tags if t)),
            "meta": {"ghsa_id": ghsa_id, "cve_ids": cves, "severity": severity},
            "source_file": str(path.name),
            "published_at": pub_dt,
        }
    except Exception:
        return None


def _parse_markdown(path: Path, category: str, id_prefix: str) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    title = _first_heading(text)
    summary = _first_paragraph(text)
    cves = _extract_cves(text)
    techniques = _extract_techniques(text)
    tags = list(dict.fromkeys(cves + techniques))

    # Add category-specific tags from filename
    stem = path.stem.lower()
    for keyword in ("volt-typhoon", "lapsus", "unc3890", "bluefield", "morpheus",
                    "doca", "container", "rdma", "gpu", "jetson", "aistore",
                    "mellanox", "cumulus", "nvue"):
        if keyword in stem:
            tags.append(keyword)

    tags = list(dict.fromkeys(tags))

    return {
        "category": category,
        "external_id": f"{id_prefix}_{path.stem}",
        "title": title,
        "summary": summary,
        "body": text,
        "tags": tags,
        "meta": {
            "cve_ids": cves,
            "attack_techniques": techniques,
        },
        "source_file": str(path.name),
        "published_at": None,
    }


# ── seeder ────────────────────────────────────────────────────────────────────

async def seed_knowledge(db: AsyncSession) -> dict[str, int]:
    records: list[dict[str, Any]] = []

    # CVE JSONs
    for p in sorted((DATA_DIR / "cve").glob("*.json")):
        rec = _parse_cve_json(p)
        if rec:
            records.append(rec)

    # PSIRT markdown analyses + GHSA JSONs
    psirt_dir = DATA_DIR / "psirt"
    for p in sorted(psirt_dir.glob("*.md")):
        records.append(_parse_markdown(p, "psirt_analysis", "psirt"))
    for p in sorted(psirt_dir.glob("GHSA-*.json")):
        rec = _parse_ghsa_json(p)
        if rec:
            records.append(rec)

    # Threat actor profiles
    for p in sorted((DATA_DIR / "threat_actors").glob("*.md")):
        records.append(_parse_markdown(p, "threat_actor", "actor"))

    # Vendor reports
    for p in sorted((DATA_DIR / "vendor_reports").glob("*.md")):
        records.append(_parse_markdown(p, "vendor_report", "vendor"))

    # Research notes
    for p in sorted((DATA_DIR / "research").glob("*.md")):
        records.append(_parse_markdown(p, "research", "research"))

    # Strategy docs
    for p in sorted((DATA_DIR / "strategy").glob("*.md")):
        records.append(_parse_markdown(p, "strategy", "strategy"))

    if not records:
        return {"inserted": 0, "skipped": 0, "total": 0}

    inserted = 0
    skipped = 0
    for rec in records:
        stmt = (
            pg_insert(KnowledgeArticle)
            .values(**rec)
            .on_conflict_do_nothing(index_elements=["external_id"])
        )
        result = await db.execute(stmt)
        if result.rowcount:
            inserted += 1
        else:
            skipped += 1

    await db.commit()
    return {"inserted": inserted, "skipped": skipped, "total": len(records)}
