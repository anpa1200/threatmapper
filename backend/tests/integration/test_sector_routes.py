import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_sector_sources_shape(client: AsyncClient):
    resp = await client.get("/api/sector/sources")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_sector_list_shape(client: AsyncClient):
    resp = await client.get("/api/sector/sectors")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_sector_region_list_shape(client: AsyncClient):
    resp = await client.get("/api/sector/regions")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_sector_technology_list_shape(client: AsyncClient):
    resp = await client.get("/api/sector/technologies")
    assert resp.status_code == 200
    assert {"id": "cloud", "label": "Cloud"} in resp.json()


@pytest.mark.asyncio
async def test_actor_relevance_empty_db_returns_list(client: AsyncClient):
    resp = await client.get(
        "/api/sector/relevance",
        params={"sector": "telecom", "region": "Israel", "days": 365},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_actor_relevance_requires_sector(client: AsyncClient):
    resp = await client.get("/api/sector/relevance")
    assert resp.status_code == 422
