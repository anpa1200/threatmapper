## Summary

Describe the change and the analyst/operator workflow it affects.

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] ATT&CK mapping correction
- [ ] Deployment / operations
- [ ] Test / CI

## Evidence

- [ ] Tests added or updated
- [ ] Documentation added or updated
- [ ] Demo data or sample output updated, if applicable
- [ ] No secrets, private reports, credentials, malware samples, or victim-sensitive data

## Checks

```bash
cd backend && PYTHONPATH=. pytest tests/unit -v
cd frontend && npm run build
```
