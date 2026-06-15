# Maintainers

ThreatMapper is maintained by Andrey Pautov.

## Ownership

| Area | Owner | Scope |
|---|---|---|
| Product direction | Andrey Pautov | CTI workflow, ATT&CK mapping model, release priorities |
| Backend | Andrey Pautov | FastAPI, PostgreSQL schema, LLM adapters, exports, scheduled ATT&CK sync |
| Frontend | Andrey Pautov | React workspace, matrix UI, comparison views, report library |
| Documentation | Andrey Pautov | README, deployment guide, analyst workflow, validation notes |

## Maintenance Policy

- Bug reports and mapping corrections are tracked through GitHub Issues.
- Security reports should follow `SECURITY.md`.
- Releases use semantic versioning once the project reaches `v1.0.0`.
- Minor releases are planned monthly while the project is active.
- Patch releases are cut as needed for broken installs, data-loss bugs, or security fixes.

## Project Status

ThreatMapper is pre-`v1.0` and should be treated as an actively developed analyst workbench. The public web workspace is suitable for exploration. Private reports should be processed only in a self-hosted deployment controlled by the operator.
