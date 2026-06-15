# Security Policy

## Supported Versions

ThreatMapper is currently pre-`v1.0`. Security fixes are applied to the latest release branch only.

| Version | Supported |
|---|---|
| latest `main` | Yes |
| latest tagged release | Yes |
| older pre-`v1.0` tags | Best effort |

## Reporting a Vulnerability

Do not open a public issue for vulnerabilities involving data exposure, authentication bypass, secret handling, arbitrary file access, or unsafe report parsing.

Report privately by email:

```text
1200km@gmail.com
```

Include:

- Affected component: frontend, API, parser, export, Docker deployment, or docs.
- Impact and attack preconditions.
- Reproduction steps.
- Whether the issue affects self-hosted deployments, the public web workspace, or both.
- Suggested mitigation if known.

## Data Handling Model

- ThreatMapper Docker stores report analysis data in the operator-controlled PostgreSQL database.
- Uploaded report text is sent only to the LLM provider configured by the operator.
- The public web workspace is for exploration and should not receive confidential, customer-sensitive, classified, or internal reports.
- Operators who need private processing should use a local or private LLM gateway and isolate the deployment behind an authenticated reverse proxy.

## Deployment Boundary

The default Docker Compose profile is for local or controlled self-hosted use. Internet-facing deployments require:

- TLS termination.
- Authentication at a reverse proxy or identity-aware gateway.
- Network restrictions for PostgreSQL, Redis, API, and worker services.
- Secret rotation and non-default database credentials.
- Backups, retention policy, and restore testing.
- Review of LLM provider data-retention terms.

## Known Security Limitations

- The default deployment is not a hardened multi-tenant SaaS.
- LLM outputs are untrusted and require analyst review.
- File parsing is bounded but should still be run in a controlled environment for untrusted documents.
- Generated detection logic is a draft and must not be deployed without local review and testing.
