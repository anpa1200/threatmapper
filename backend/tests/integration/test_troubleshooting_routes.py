from __future__ import annotations

from httpx import AsyncClient


class _FakeAdapter:
    provider = "local"
    model = "test-model"

    async def _raw_complete(self, system: str, user: str) -> str:
        assert "AdversaryGraph troubleshooting assistant" in system
        assert "attck_storage_writable" in user
        return """
        {
          "severity": "high",
          "summary": "ATT&CK cache is not writable.",
          "likely_root_cause": "The mounted ATT&CK cache volume is root-owned.",
          "immediate_actions": ["Fix volume ownership", "Restart API"],
          "validation_commands": ["docker compose exec -T api sh -lc 'ls -ld /app/data/attck'"],
          "evidence_to_collect": ["Self-test output", "API logs"],
          "do_not_do": ["Do not delete volumes without backup"]
        }
        """


async def test_troubleshooting_assistant_uses_llm_when_available(client: AsyncClient, monkeypatch):
    monkeypatch.setattr("app.api.routes.troubleshooting.get_adapter", lambda provider, model=None: _FakeAdapter())
    response = await client.post("/api/troubleshooting/assistant", json={
        "provider": "local",
        "operator_notes": "self-test failed: attck_storage_writable permission denied",
        "selftest_result": {
            "status": "error",
            "version": "5.6.0",
            "checked_at": "2026-07-02T00:00:00Z",
            "duration_ms": 10,
            "checks": [
                {"name": "attck_storage_writable", "status": "error", "message": "Permission denied", "details": {}},
            ],
        },
    })
    assert response.status_code == 200
    body = response.json()
    assert body["ai_used"] is True
    assert body["severity"] == "high"
    assert "volume" in body["likely_root_cause"].lower()
    assert body["validation_commands"]


async def test_troubleshooting_assistant_falls_back_when_provider_fails(client: AsyncClient, monkeypatch):
    def broken_adapter(provider, model=None):
        raise RuntimeError("not configured")

    monkeypatch.setattr("app.api.routes.troubleshooting.get_adapter", broken_adapter)
    response = await client.post("/api/troubleshooting/assistant", json={
        "provider": "claude",
        "operator_notes": "/app/data/attck Permission denied",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["ai_used"] is False
    assert body["severity"] == "high"
    assert "attck-data-permissions" in " ".join(body["validation_commands"])


async def test_troubleshooting_assistant_rejects_invalid_provider(client: AsyncClient):
    response = await client.post("/api/troubleshooting/assistant", json={
        "provider": "bad-provider",
        "operator_notes": "test",
    })
    assert response.status_code == 422
