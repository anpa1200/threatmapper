"""Integration tests for /api/retrohunt routes."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_retrohunt_signals_returns_list(client: AsyncClient):
    response = await client.get("/api/retrohunt/signals")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_retrohunt_signals_invalid_limit_returns_422(client: AsyncClient):
    response = await client.get("/api/retrohunt/signals", params={"limit": 9999})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_retrohunt_signals_invalid_days_returns_422(client: AsyncClient):
    response = await client.get("/api/retrohunt/signals", params={"days": 0})
    assert response.status_code == 422
