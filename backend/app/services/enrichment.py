from __future__ import annotations

import httpx


async def enrich_observable(kind: str, value: str, provider: str = "auto") -> dict:
    chosen = provider
    if provider == "auto":
        chosen = "rdap" if kind in {"ipv4", "ipv6", "domain"} else "local"
    if chosen == "local":
        return {"provider": "local", "status": "complete", "verdict": "unknown", "confidence": 0, "raw_data": {"note": "No configured public provider for this observable type"}}
    if chosen != "rdap":
        raise ValueError(f"Unsupported enrichment provider: {provider}")
    path = "ip" if kind in {"ipv4", "ipv6"} else "domain"
    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        response = await client.get(f"https://rdap.org/{path}/{value}", headers={"User-Agent": "ThreatMapper/0.8"})
        response.raise_for_status()
    data = response.json()
    return {
        "provider": "rdap", "status": "complete", "verdict": "unknown", "confidence": 0,
        "raw_data": {"handle": data.get("handle"), "name": data.get("name"), "country": data.get("country"), "entities": data.get("entities", [])[:10]},
    }
