"""Integration tests for /api/export routes."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_export_analysis_invalid_id_returns_400(client: AsyncClient):
    response = await client.get("/api/export/analysis/not-a-uuid")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_export_analysis_unknown_session_returns_404(client: AsyncClient):
    response = await client.get("/api/export/analysis/00000000-0000-0000-0000-000000000010")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_export_stix_invalid_id_returns_400(client: AsyncClient):
    response = await client.get("/api/export/analysis/not-a-uuid/stix")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_export_stix_unknown_session_returns_404(client: AsyncClient):
    response = await client.get("/api/export/analysis/00000000-0000-0000-0000-000000000011/stix")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_export_layer_missing_body_returns_422(client: AsyncClient):
    response = await client.post("/api/export/layer", json={})
    assert response.status_code == 422
