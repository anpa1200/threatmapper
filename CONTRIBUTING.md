# Contributing

ThreatMapper welcomes focused contributions that improve CTI analyst workflows, documentation, validation, and operational reliability.

## Good First Contributions

- Fix broken documentation or unclear setup steps.
- Add safe public demo reports.
- Improve sample outputs.
- Add tests for parsing, ATT&CK mapping, exports, or API validation.
- Report incorrect ATT&CK mappings with evidence.
- Improve deployment hardening guidance.

## Before Opening a Pull Request

1. Keep the change scoped.
2. Add or update tests when behavior changes.
3. Update documentation for user-facing changes.
4. Do not commit secrets, private reports, customer data, malware samples, or credentials.
5. Run the relevant checks:

```bash
cd backend
PYTHONPATH=. pytest tests/unit -v

cd ../frontend
npm ci
npm run build
```

## Mapping Corrections

For ATT&CK mapping issues, include:

- Source report URL or public citation.
- Exact text that supports the technique.
- Current mapped technique.
- Proposed corrected technique.
- Reasoning and confidence.

## Pull Request Style

- Use neutral language.
- Prefer evidence over claims.
- Avoid broad rewrites unless the change is explicitly documentation-only.
- Keep generated build artifacts out of the PR unless the repo section already tracks them.
