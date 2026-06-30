# AdversaryGraph v5.5.0 Release Summary

AdversaryGraph v5.5.0 focuses on enterprise access controls for teams running
the platform in controlled self-hosted environments.

## Added

- Expanded RBAC roles for threat intelligence, detection engineering, incident
  response, auditing, service accounts, security administration, and platform
  administration.
- Per-user permission overrides layered on top of role defaults.
- Password policy settings exposed through environment, Docker Compose, and
  Helm configuration.
- MFA setup, confirmation, and admin disable workflow support for local users.
- Session inventory, self-service revoke-all, and admin user-session revocation.
- Trusted reverse-proxy SSO metadata for OIDC/SAML deployments fronted by an
  identity-aware gateway.
- Authentication audit history for logins, failed logins, MFA failures, logout,
  user changes, password resets, session revocation, feed sync, exports, SIEM
  forwarding, and file uploads.

## Updated

- Admin Panel now exposes users, effective permissions, sessions, MFA state, and
  audit history in one operational view.
- Login page supports MFA code entry when the account requires it.
- Auth guide, admin guide, production-readiness guide, Docker Compose examples,
  `.env.example`, and Helm values document the enterprise access controls.

## Validation

- Backend auth integration tests cover login, user CRUD, password reset, and
  session behavior.
- Frontend production build validates the updated login and Admin Panel pages.
- Docker Compose and Helm configuration render with the new auth settings.

## Security Notes

Native auth is intended for controlled self-hosted deployments. Internet-facing
production deployments should still place AdversaryGraph behind TLS, a trusted
reverse proxy, and an enterprise identity provider when possible.
