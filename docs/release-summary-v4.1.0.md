# AdversaryGraph v4.1.0 Release Summary

AdversaryGraph v4.1.0 adds Asset Attack Surface Mapping to the self-hosted
platform. The release expands the workflow from report, IOC, actor, and malware
analysis into infrastructure-first review: upload or paste an asset inventory,
normalize assets, score exposure, map likely ATT&CK candidates, and send the
result into Navigator as a white comparison layer.

## Highlights

- Asset inventory ingestion for CSV, JSON, TXT, scanner output, cloud inventory,
  CMDB exports, and hostname/IP lists.
- Deterministic exposure and risk scoring for internet-facing, internal,
  third-party, and unknown assets.
- ATT&CK technique candidates for public web/API surfaces, remote access,
  identity infrastructure, databases, cloud storage, containers, CI/CD, and
  legacy systems.
- Optional AI enrichment for executive summary, attack-path hypotheses, control
  gaps, validation gaps, assumptions, and priority actions.
- Saved backend cases for previous asset analyses, with reload and delete
  actions.
- White asset-surface TTP layer in Navigator so inventory-derived candidates are
  visually distinct from manual selections and other comparison layers.
- Updated Discover launchers for Asset Surface and the newer malware-analysis
  tools.
- Sidebar scrolling fix for long navigation lists.
- Current v4.1 screenshots and validation notes in
  `docs/assets/adversarygraph-v4.1-platform/manifest.md`.

## Validation

- Backend Asset Surface unit tests cover CSV/TXT parsing, deterministic scoring,
  ATT&CK candidate mapping, and AI fallback behavior.
- Frontend production build validates the new Asset Surface page, Discover
  launchers, Navigator white layer handling, and clickable TTP/IOC rendering.
- Local screenshot capture validates the current Docker-served UI at
  `http://localhost:3000`.

## Links

- Detailed notes: `docs/release-notes/v4.1.0.md`
- Asset Surface guide: `docs/asset-attack-surface.md`
- Platform guide: `docs/adversarygraph-platform-guide.md`
- Screenshot manifest: `docs/assets/adversarygraph-v4.1-platform/manifest.md`
