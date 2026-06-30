from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query, Response

from app.core.config import settings
from app.core.observability import observability_state

router = APIRouter(prefix="/observability", tags=["Observability"])


def _tail_lines(path: Path, limit: int) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    return [line.rstrip("\n") for line in lines[-limit:]]


def _redact_log_line(line: str) -> str:
    redacted = line
    markers = ("token=", "api_key=", "apikey=", "password=", "secret=", "Authorization:")
    for marker in markers:
        lower = redacted.lower()
        idx = lower.find(marker.lower())
        while idx >= 0:
            start = idx + len(marker)
            end = start
            while end < len(redacted) and not redacted[end].isspace():
                end += 1
            redacted = f"{redacted[:start]}[REDACTED]{redacted[end:]}"
            lower = redacted.lower()
            idx = lower.find(marker.lower(), start + len("[REDACTED]"))
    return redacted


@router.get("/summary")
async def observability_summary() -> dict[str, Any]:
    log_path = Path(settings.log_dir) / "adversarygraph-api.log"
    snapshot = observability_state.snapshot()
    snapshot["log_file"] = {
        "path": str(log_path),
        "exists": log_path.exists(),
        "size_bytes": log_path.stat().st_size if log_path.exists() else 0,
    }
    return snapshot


@router.get("/traces")
async def recent_traces(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    traces = observability_state.snapshot()["recent_traces"][:limit]
    return {"items": traces, "limit": limit}


@router.get("/logs")
async def api_logs(limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    log_path = Path(settings.log_dir) / "adversarygraph-api.log"
    lines = [_redact_log_line(line) for line in _tail_lines(log_path, limit)]
    return {
        "path": str(log_path),
        "exists": log_path.exists(),
        "limit": limit,
        "lines": lines,
    }


@router.get("/metrics")
async def prometheus_metrics() -> Response:
    return Response(
        content=observability_state.prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
