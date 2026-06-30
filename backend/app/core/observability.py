from __future__ import annotations

from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import Lock
from time import perf_counter
from typing import Any


@dataclass
class RequestTrace:
    request_id: str
    method: str
    path: str
    status_code: int
    duration_ms: float
    timestamp: str
    client: str
    error: str = ""


class ObservabilityState:
    def __init__(self, trace_limit: int = 500) -> None:
        self.started_at = datetime.now(timezone.utc)
        self._lock = Lock()
        self._requests_total = 0
        self._requests_by_status: Counter[str] = Counter()
        self._requests_by_route: Counter[str] = Counter()
        self._latency_sum_ms = 0.0
        self._latency_max_ms = 0.0
        self._last_error: dict[str, Any] | None = None
        self._traces: deque[RequestTrace] = deque(maxlen=trace_limit)

    @property
    def uptime_seconds(self) -> int:
        return int((datetime.now(timezone.utc) - self.started_at).total_seconds())

    def record_request(
        self,
        *,
        request_id: str,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        client: str,
        error: str = "",
    ) -> None:
        status_family = f"{int(status_code / 100)}xx" if status_code else "error"
        now = datetime.now(timezone.utc).isoformat()
        trace = RequestTrace(
            request_id=request_id,
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=round(duration_ms, 2),
            timestamp=now,
            client=client,
            error=error,
        )
        with self._lock:
            self._requests_total += 1
            self._requests_by_status[status_family] += 1
            self._requests_by_route[f"{method} {path}"] += 1
            self._latency_sum_ms += duration_ms
            self._latency_max_ms = max(self._latency_max_ms, duration_ms)
            if status_code >= 500 or error:
                self._last_error = asdict(trace)
            self._traces.appendleft(trace)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            avg_latency = self._latency_sum_ms / self._requests_total if self._requests_total else 0.0
            recent = [asdict(trace) for trace in list(self._traces)[:50]]
            top_routes = [
                {"route": route, "count": count}
                for route, count in self._requests_by_route.most_common(20)
            ]
            return {
                "started_at": self.started_at.isoformat(),
                "uptime_seconds": self.uptime_seconds,
                "requests_total": self._requests_total,
                "requests_by_status": dict(self._requests_by_status),
                "top_routes": top_routes,
                "latency": {
                    "avg_ms": round(avg_latency, 2),
                    "max_ms": round(self._latency_max_ms, 2),
                },
                "last_error": self._last_error,
                "recent_traces": recent,
            }

    def prometheus_text(self) -> str:
        snapshot = self.snapshot()
        lines = [
            "# HELP adversarygraph_uptime_seconds API process uptime in seconds.",
            "# TYPE adversarygraph_uptime_seconds gauge",
            f"adversarygraph_uptime_seconds {snapshot['uptime_seconds']}",
            "# HELP adversarygraph_requests_total Total HTTP requests observed by the API middleware.",
            "# TYPE adversarygraph_requests_total counter",
            f"adversarygraph_requests_total {snapshot['requests_total']}",
            "# HELP adversarygraph_request_latency_average_ms Average observed API request latency in milliseconds.",
            "# TYPE adversarygraph_request_latency_average_ms gauge",
            f"adversarygraph_request_latency_average_ms {snapshot['latency']['avg_ms']}",
            "# HELP adversarygraph_request_latency_max_ms Maximum observed API request latency in milliseconds.",
            "# TYPE adversarygraph_request_latency_max_ms gauge",
            f"adversarygraph_request_latency_max_ms {snapshot['latency']['max_ms']}",
        ]
        for family, count in sorted(snapshot["requests_by_status"].items()):
            lines.append(
                f'adversarygraph_requests_by_status_total{{status_family="{family}"}} {count}'
            )
        return "\n".join(lines) + "\n"


observability_state = ObservabilityState()


def monotonic_ms_since(started: float) -> float:
    return (perf_counter() - started) * 1000
