# AdversaryGraph v5.3.0 Release Summary

Release date: 2026-06-30

AdversaryGraph v5.3.0 promotes the native authentication and user-management
documentation set. The release adds a local authentication guide page that can
be opened from the running platform and from the sign-in screen, so operators
can configure access control before exposing the workspace to other users.

## What Changed

- Added `/auth-guide` as an unauthenticated local setup guide for native auth.
- Added a direct sign-in page link to the authentication setup guide.
- Documented viewer, analyst, and admin role boundaries.
- Documented bootstrap admin creation and cleanup of
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD` after permanent named admins exist.
- Documented password reset and disabled-user session revocation behavior.
- Updated quickstart, admin, security, production-readiness, and privacy
  guidance for native username/password auth plus optional identity-aware
  reverse-proxy deployments.
- Updated release metadata to v5.3.0 across backend, frontend, README, roadmap,
  security policy, version matrix, and consistency checks.

## Operator Guidance

Use native authentication for controlled self-hosted deployments:

```env
AUTH_ENABLED=true
AUTH_DEFAULT_ROLE=viewer
AUTH_SESSION_MINUTES=720
AUTH_BOOTSTRAP_ADMIN_USERNAME=admin
AUTH_BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-temporary-password
```

After first login, create permanent named admin accounts in **Admin Panel**,
clear `AUTH_BOOTSTRAP_ADMIN_PASSWORD`, and restart the API container.

For exposed deployments, still put the platform behind TLS and restrict direct
access to the API, PostgreSQL, Redis, MalwareGraph, and lab fixtures.

## Validation

- Version consistency script passes for v5.3.0.
- Frontend production build passes.
- Backend ruff lint passes.
- Backend test suite passes with `AUTH_ENABLED=false` for route-level tests:
  271 passed, 10 skipped.
