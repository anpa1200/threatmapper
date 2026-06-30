# Roadmap

Current release: **v5.1.0** — Attack Simulation telemetry fidelity and review hardening (2026-06-30)

For the full history from v0.2.0 through v5.1.0 see [CHANGELOG.md](CHANGELOG.md).

## v5.x — Hardening Sprint (in progress)

The current sprint focuses on security hardening, test coverage, and reviewer readiness. No new product features until this sprint closes.

- [x] Migrate the legacy Gemini SDK package to `google-genai` (SDK renamed by Google)
- [x] Expand CI: add ruff lint, pip-audit, npm audit, Docker build checks, container scan (Trivy), secret scan (gitleaks)
- [x] Add route-level integration tests for high-risk mutating Operations and Pipeline endpoints
- [x] Publish reviewer guide and demo dataset
- [x] Document Starlette transitive dependency version and CVE status
- [ ] Raise backend coverage gate from the current conservative baseline
- [ ] Add frontend unit tests for Attack Simulation and Asset Surface critical flows

## v5.1 — Review Hardening

- [x] Enforce source-correct telemetry policy for Attack Simulation and AI-assisted scenarios
- [x] Document telemetry fidelity architecture and SIEM validation boundaries
- [ ] Enforced backend coverage gate at 70%
- [ ] Frontend unit tests with Vitest
- [ ] Authentication hardening guide for reverse-proxy deployments
- [ ] `.env.example` credential rotation documentation

## Backlog

- Optional local LLM gateway profile (Ollama / LM Studio)
- STIX/TAXII export mode
- Case timeline view
- ATT&CK version-diff view for mappings across releases
- Mapping evaluation harness for public CTI reports
- STIX 2.1 bundle export
