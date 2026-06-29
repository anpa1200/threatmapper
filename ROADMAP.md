# Roadmap

Current release: **v5.0.0** — Attack Simulation and SIEM Validation (2026-06-29)

For the full history from v0.2.0 through v5.0.0 see [CHANGELOG.md](CHANGELOG.md).

## v5.x — Hardening Sprint (in progress)

The current sprint focuses on security hardening, test coverage, and reviewer readiness. No new product features until this sprint closes.

- [ ] Migrate `google-generativeai` → `google-genai` (SDK renamed by Google)
- [ ] Expand CI: add ruff lint, pip-audit, npm audit, Docker build checks, container scan (Trivy), secret scan (gitleaks)
- [ ] Add route-level integration tests for all mutating endpoints
- [ ] Publish reviewer guide and demo dataset
- [ ] Document Starlette transitive dependency version and CVE status

## v5.1 — Review Hardening (planned)

- Enforced backend coverage gate at 70%
- Frontend unit tests with Vitest
- Authentication hardening guide for reverse-proxy deployments
- `.env.example` credential rotation documentation

## Backlog

- Optional local LLM gateway profile (Ollama / LM Studio)
- STIX/TAXII export mode
- Case timeline view
- ATT&CK version-diff view for mappings across releases
- Mapping evaluation harness for public CTI reports
- STIX 2.1 bundle export
