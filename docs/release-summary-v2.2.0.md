# AdversaryGraph v2.2.0 Release Summary

AdversaryGraph v2.2.0 is the operational troubleshooting and deployment
self-test release.

The release makes Docker startup problems easier to diagnose from inside the
application. API errors now show clear context, provide a direct link to an
internal troubleshooting page, and include a `Recheck` action that reruns the
deployment self-test. If the system is healthy, the popup turns green and shows
`All correct.`.

## What Changed Since v2.1.1

- Internal `/troubleshooting` page added to the Docker app.
- API error popup now shows status, URL, and message context.
- API error popup now includes `Recheck`.
- Recheck calls `/api/system/selftest`.
- Passing recheck changes the popup to green with `All correct.`.
- Startup self-test errors link to troubleshooting.
- Matrix data queries retry longer during startup.
- Matrix/discover/sync data refresh after self-test passes.
- Docker `selftest` service validates API, database, Redis, and ATT&CK/ATLAS
  data.

## Operator Value

- Faster diagnosis after `docker compose up`.
- Clearer distinction between API startup timing, database problems, Redis
  problems, and missing ATT&CK data.
- Fewer stale empty-matrix states after the backend becomes healthy.
- Built-in recovery commands for common local deployment issues.

## Verification

- Frontend build passed.
- Docker self-test passed.
- `/api/system/selftest` returned `ok`.
- `/troubleshooting` route is served by the Docker frontend.
- Live frontend source includes `Recheck` and `All correct.` behavior.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.2.0
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.2.0.md`
