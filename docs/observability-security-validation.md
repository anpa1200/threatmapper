# Observability, Security Scanning, And Validation Evidence

AdversaryGraph now exposes an operator-facing observability layer for controlled self-hosted deployments. The goal is to make production readiness measurable: health checks, request traces, API metrics, safe log review, and repeatable security scans.

## Runtime Observability

| Surface | Path | Purpose |
|---|---|---|
| Health | `/api/health` | Lightweight liveness/version check |
| Self-test | `/api/system/selftest` | Database, Redis, ATT&CK/ATLAS, IOC feed, CVE feed, CPU, memory, and provider-key readiness |
| Dashboard | `/observability` | UI view for API uptime, request counts, latency, recent traces, top routes, log tail, and metrics preview |
| Summary API | `/api/observability/summary` | JSON snapshot for dashboards and automation |
| Recent traces | `/api/observability/traces` | Recent request trace ring buffer with request ID, method, path, status, latency, and timestamp |
| Log tail | `/api/observability/logs` | Redacted tail of `adversarygraph-api.log` |
| Prometheus text | `/api/observability/metrics` | Prometheus-compatible counters and gauges |

The request middleware assigns or preserves `X-Request-ID`, records latency and status family, and writes structured log lines to both stdout and the rotating API log file.

## What Is Logged

The API log records:

- request ID
- method
- path
- HTTP status code
- request duration
- exception class for failed requests

The observability log-tail endpoint redacts common credential markers such as `token=`, `api_key=`, `password=`, `secret=`, and `Authorization:`.

Do not treat this as a full SIEM audit replacement. It is an operator dashboard and troubleshooting layer. Security-relevant user actions are still stored through the platform audit-event model where implemented.

## Prometheus Integration

The metrics endpoint returns text in Prometheus exposition format:

```text
adversarygraph_uptime_seconds
adversarygraph_requests_total
adversarygraph_request_latency_average_ms
adversarygraph_request_latency_max_ms
adversarygraph_requests_by_status_total{status_family="2xx"}
```

For cloud deployments, scrape the endpoint through the authenticated frontend/API boundary or use a trusted reverse proxy that injects a service identity.

## Security Scanning

Run the local security validation wrapper:

```bash
make security-scan
```

The wrapper runs:

| Check | Tool |
|---|---|
| Backend lint/SAST baseline | `ruff` |
| Backend SAST | `bandit` at medium/high severity |
| Backend dependency audit | `pip-audit` |
| Frontend dependency audit | `npm audit --audit-level=high` |
| Secret scan | `gitleaks` when installed |
| Compose validation | `docker compose config --quiet` |
| Container scan | `trivy` when installed |

CI installs and runs the required hosted tools for dependency audit, SAST, secret scanning, container scanning, Docker builds, frontend build, backend tests, and version consistency.

## Latest Local Validation Snapshot

The current local validation run completed with:

- `ruff check .`: passed
- `bandit -q -r app -x "tests,app/data" --severity-level medium --confidence-level medium`: passed
- `pip-audit -r requirements.txt`: no known vulnerabilities found
- `npm audit --audit-level=high`: found 0 vulnerabilities
- `docker compose config --quiet`: passed
- focused backend route tests: 22 passed
- frontend production build: passed

Local host note: `gitleaks` and `trivy` were not installed on the workstation during this run, so the local wrapper skipped those two host-tool checks. GitHub Actions still runs gitleaks and Trivy in CI.

## Validation Examples

Recommended evidence to capture for release validation:

1. `/observability` dashboard showing request volume, status counters, traces, and log tail.
2. `/troubleshooting` self-test popup or self-test report.
3. Attack Simulation real-time telemetry page after a lab scenario.
4. SIEM forwarding result after sending lab telemetry.
5. CVE Library feed status and correlation detail.
6. Admin Panel showing role-based access management.
7. CI run with backend tests, SAST, dependency audit, secret scan, and container scan.

These screenshots should be used as validation examples, not as proof of production compromise or real-world attack execution.
