import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_cve_sources_shape(client: AsyncClient):
    resp = await client.get("/api/cve/sources")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_cve_library_shape(client: AsyncClient):
    resp = await client.get("/api/cve/library", params={"search": "CVE-2026", "severity": "HIGH", "limit": 25})
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["total"], int)
    assert body["limit"] == 25
    assert body["offset"] == 0
    assert isinstance(body["items"], list)


@pytest.mark.asyncio
async def test_missing_cve_returns_404(client: AsyncClient):
    resp = await client.get("/api/cve/CVE-2099-99999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sync_status_includes_cve_source(client: AsyncClient, monkeypatch):
    from app.services.attck import version_checker

    class Status:
        domain = "enterprise-attack"
        current_version = "19.1"
        latest_version = "19.1"
        needs_update = False
        last_ingested = "2026-06-30"

    monkeypatch.setattr(version_checker, "get_status", lambda: [Status()])
    resp = await client.get("/api/sync/status")
    assert resp.status_code == 200
    source_ids = {source["id"] for source in resp.json()["sources"]}
    assert "cve-intelligence" in source_ids
