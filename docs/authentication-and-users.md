# Authentication and User Management

AdversaryGraph supports native username/password authentication for private
deployments and trusted reverse-proxy SSO for operators who use OIDC or SAML at
an identity-aware gateway.

The same operator guide is available in a running local instance at:

- <http://localhost:3000/auth-guide>

The login page links directly to this guide, and the route remains accessible
before sign-in when `AUTH_ENABLED=true`.

## Roles

| Role | Access |
| --- | --- |
| `viewer` | Read-only workspace access, matrix navigation, libraries, reports, and lookups. |
| `analyst` | Viewer access plus operational workflows such as attack simulation, feeds, pipeline, and cases. |
| `threat_intel` | CTI-focused workflows: reports, APT/IOC/CVE views, feeds, enrichment, and exports. |
| `detection_engineer` | Detection workflows: rule generation, coverage review, attack simulation, SIEM forwarding, and validation. |
| `incident_responder` | Investigation workflows: IOC pivots, uploads, response cases, attack simulation, and SIEM forwarding. |
| `auditor` | Read-only access plus audit and export review. |
| `security_admin` | User, session, MFA, password, and audit administration. |
| `service_account` | API automation for sync, analysis, SIEM forwarding, and exports. |
| `admin` | Full platform administration. |

Roles map to permissions. Admin inherits all permissions. Analyst-style roles
inherit viewer access. The Admin Panel can also grant explicit extra
permissions to a user when a coarse role is not precise enough.

Current permissions are:

`read`, `run_analysis`, `manage_intel`, `manage_detections`,
`run_attack_simulation`, `manage_feeds`, `forward_siem`, `upload_files`,
`export_data`, `manage_users`, `manage_auth`, and `view_audit`.

## Enable Native Login

Set these values in `.env`:

```env
AUTH_ENABLED=true
AUTH_SSO_MODE=proxy
AUTH_DEFAULT_ROLE=viewer
AUTH_SESSION_MINUTES=720
AUTH_PASSWORD_MIN_LENGTH=12
AUTH_BOOTSTRAP_ADMIN_USERNAME=admin
AUTH_BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-temporary-password
```

Start or restart the API container. If no users exist, the API creates the first
administrator from `AUTH_BOOTSTRAP_ADMIN_USERNAME` and
`AUTH_BOOTSTRAP_ADMIN_PASSWORD`.

After signing in and creating permanent named admin accounts, clear
`AUTH_BOOTSTRAP_ADMIN_PASSWORD` and restart the API. Existing users remain in the
database.

For Docker Compose deployments, `docker-compose.yml` passes these variables to
the API, worker, and beat services. The worker and beat receive the same auth
settings so background API clients and scheduled workflows have a consistent
runtime configuration.

## Sign In

When `AUTH_ENABLED=true`, the web application opens on the protected login page.
Successful login creates an HttpOnly session cookie named `ag_session`. API
clients can also use the returned bearer token.

If local MFA is enabled for a user, the login request must also include a TOTP
code. The UI includes an optional MFA code field.

## Admin Panel

Open **Admin Panel** from the sidebar as an admin user.

Admins can:

- create users;
- assign any built-in role;
- add or remove explicit permission grants;
- enable or disable users;
- reset passwords;
- view recent sessions;
- revoke all sessions for a user;
- disable local MFA for a user;
- review auth audit events.

The UI never displays stored password hashes. Passwords are hashed with
PBKDF2-HMAC-SHA256 and per-user random salts.

Password resets and disabled accounts revoke active native sessions for the
affected user.

## Session Management

Native sessions expire after `AUTH_SESSION_MINUTES`. The Admin Panel lists recent
sessions with user, IP, user-agent, expiry, and active/revoked state.

Available session controls:

- logout revokes the current session;
- password reset revokes all sessions for the affected user;
- disable user revokes all sessions for the affected user;
- admins can revoke all sessions for any user;
- users can revoke their other sessions through `POST /api/auth/sessions/revoke-all`.

## Password Policy And MFA

Local password policy is controlled by:

```env
AUTH_PASSWORD_MIN_LENGTH=12
AUTH_PASSWORD_REQUIRE_UPPER=false
AUTH_PASSWORD_REQUIRE_LOWER=false
AUTH_PASSWORD_REQUIRE_NUMBER=false
AUTH_PASSWORD_REQUIRE_SPECIAL=false
AUTH_MFA_ENABLED=false
```

TOTP MFA endpoints are available for local accounts:

- `POST /api/auth/mfa/setup` starts setup and returns the TOTP secret and
  `otpauth://` URL;
- `POST /api/auth/mfa/confirm` verifies a code and enables MFA;
- `POST /api/auth/users/{user_id}/mfa/disable` lets an auth administrator reset
  MFA for a user.

For enterprise deployments, prefer enforcing MFA in the OIDC/SAML IdP and using
local MFA only for break-glass native accounts.

## OIDC/SAML SSO Through Trusted Proxy

AdversaryGraph does not terminate OIDC or SAML directly. The supported
enterprise pattern is to terminate identity at a trusted reverse proxy or ingress
controller, then forward signed identity headers to the API.

Required operator controls:

- set `AUTH_ENABLED=true`;
- set `AUTH_SSO_MODE=oidc-proxy` or `AUTH_SSO_MODE=saml-proxy`;
- set a strong `PROXY_SECRET`;
- configure the proxy to send `X-Auth-User`, `X-Auth-Roles`, and
  `X-Internal-Proxy-Secret`;
- strip any client-supplied `X-Auth-User`, `X-Auth-Roles`, and
  `X-Internal-Proxy-Secret` before forwarding traffic to the API.

If `PROXY_SECRET` is configured and the request does not include the correct
internal secret, AdversaryGraph ignores all trusted-header identity fields and
falls back to native session or bearer-token authentication.

Recommended proxy examples:

- oauth2-proxy with OIDC;
- Pomerium;
- Authelia;
- Keycloak or Dex behind an ingress external-auth layer;
- SAML-capable enterprise gateway that can emit trusted headers.

Map IdP groups to AdversaryGraph roles in `X-Auth-Roles`.

## Audit Logs

Auth audit events are stored in the `audit_events` table and visible in the
Admin Panel. Events include:

- login success and failure;
- MFA failure, setup, enable, and admin disable;
- logout;
- user create/update/disable;
- password reset;
- session listing and session revocation.

The broader platform already writes audit events for report analysis, imports,
feed sync, CVE sync, IOC enrichment, SIEM forwarding, attack simulation,
asset-surface cases, saved layers, and operational objects.

## Security Notes

- Do not expose an instance with `AUTH_ENABLED=false` to untrusted networks.
- Put production deployments behind TLS.
- Use unique named accounts instead of shared admin users.
- Prefer OIDC/SAML SSO through a trusted identity-aware proxy for enterprise access.
- Require MFA at the IdP and on local break-glass admin accounts.
- Review auth audit events after user, export, feed-sync, SIEM-forwarding, and upload activity.
- Rotate bootstrap credentials after initial setup by clearing
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD`.
- Keep `AUTH_BOOTSTRAP_ADMIN_PASSWORD` blank after bootstrap; otherwise a fresh
  empty database can recreate that bootstrap account.
- Restrict direct network access to the API container.
