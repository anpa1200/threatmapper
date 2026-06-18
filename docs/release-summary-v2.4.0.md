# AdversaryGraph v2.4.0 Release Summary

AdversaryGraph v2.4.0 is the dynamic reference database and IOC consistency
release.

The release separates long-lived analyst data from rebuildable public reference
data. Docker deployments now keep Postgres data in an external deployment
directory by default, while a daily sync task refreshes public ATT&CK, MISP
Galaxy, and IOC source material.

## What Changed Since v2.2.0

- Added daily dynamic reference DB synchronization through Celery Beat.
- Added `ADVERSARYGRAPH_DB_DIR` for external persistent Postgres storage.
- Mounted Postgres data at `./data/postgres` by default instead of a hidden
  Docker named volume.
- Added `POST /api/sync/dynamic-db` for manual public reference refresh.
- Added a Reference Sync UI button for dynamic DB refresh.
- Added `scripts/migrate-postgres-volume-to-external-dir.sh` for existing
  deployments.
- Extended `/api/system/selftest` with database host/name and external data
  directory details.
- Fixed actor IOC count mismatch in the ATT&CK Group Library. The sidebar and
  actor IOC tab now both use current active 180-day IOC counts.

## Operator Value

- `git pull && docker compose up -d --build` can rebuild containers without
  hiding analyst data in an implicit Docker volume.
- Public reference intelligence can refresh daily without deleting private
  reports, custom IOC feeds, custom IOCs, or local actor mappings.
- Operators can manually refresh the reference DB from the UI or API.
- IOC counts now have consistent semantics across actor list and actor detail
  views.

## Verification

- Backend IOC route tests passed.
- Frontend production build passed.
- Docker Compose configuration validated.
- Local Docker deployment rebuilt successfully.
- `/api/health` returned `ok`.
- `/api/system/selftest` returned `ok`.
- APT1 IOC count API and actor summary both returned the same current count.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.4.0
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.4.0.md`
