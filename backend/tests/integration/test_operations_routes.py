import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_operations_lists_return_arrays(client: AsyncClient):
    for path in ("investigations", "intake", "detections", "tracked-actors"):
        response = await client.get(f"/api/operations/{path}")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_investigation_validation(client: AsyncClient):
    response = await client.post("/api/operations/investigations", json={"name": ""})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_detection_validation(client: AsyncClient):
    response = await client.post("/api/operations/detections", json={"title": "Candidate"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_invalid_operational_id(client: AsyncClient):
    response = await client.delete("/api/operations/investigations/not-a-uuid")
    assert response.status_code == 400
