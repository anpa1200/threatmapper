import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_pipeline_lists_and_identity(client: AsyncClient):
    for path in ("sources", "runs", "observables", "detections/versions", "audit"):
        response = await client.get(f"/api/pipeline/{path}")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    me = await client.get("/api/pipeline/me")
    assert me.json()["name"] == "local"


@pytest.mark.asyncio
async def test_detection_validation_endpoint(client: AsyncClient):
    response = await client.post("/api/pipeline/detections/validate", json={"format": "sigma", "content": ""})
    assert response.status_code == 200
    assert response.json()["valid"] is False
