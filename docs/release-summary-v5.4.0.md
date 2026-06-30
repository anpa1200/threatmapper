# AdversaryGraph v5.4.0 Release Summary

Release date: 2026-06-30

AdversaryGraph v5.4.0 adds operator observability and strengthens validation
evidence for reviewers. The release focuses on making the self-hosted platform
easier to monitor, troubleshoot, and assess before production or public review.

## What Changed

- Added the authenticated `/observability` dashboard.
- Added API request metrics, status-family counters, top route counts, recent
  request traces, average and maximum latency, last error tracking, and redacted
  API log tail.
- Added a Prometheus-compatible metrics endpoint at
  `/api/observability/metrics`.
- Added backend observability API routes for summary, traces, logs, and metrics.
- Added `make security-scan` and `scripts/security-scan.sh`.
- Added backend SAST coverage to CI with Bandit.
- Fixed SAST findings around weak hash usage and XML parsing.
- Added screenshot-backed observability, security scanning, and validation
  documentation.

## Validation

- Backend observability route tests pass.
- Frontend production build passes.
- Public docs production build passes.
- Ruff passes.
- Bandit SAST passes for medium/high confidence checks.
- `pip-audit` reports no known Python dependency vulnerabilities.
- `npm audit --audit-level=high` reports no frontend vulnerabilities.
- Docker Compose config validation passes.

Local Gitleaks and Trivy execution depends on the tools being installed, while
CI covers secret scanning and container scanning.
