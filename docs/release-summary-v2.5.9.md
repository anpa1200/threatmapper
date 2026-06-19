# AdversaryGraph v2.5.9 Release Summary

AdversaryGraph v2.5.9 improves the CTI-to-detection workflow.

Detection Studio can now import a default public YARA source, generate YARA-L
rules, and optionally use AI providers to draft analyst-review detection content
for Sigma, YARA, YARA-L, KQL, SPL, and EQL.

## Operator Value

- Default detection feed setup now includes SigmaHQ and the public Yara-Rules
  malware feed.
- The YARA defaults use explicit raw rule URLs, so Docker deployments do not
  require GitHub API tree access or `git`.
- Detection Studio can generate analyst-review YARA-L skeletons for Chronicle /
  Google SecOps-style handoff.
- Detection Studio can optionally generate detection rules with local, Claude,
  OpenAI, Gemini, or MiniMax providers.
- AI generation accepts telemetry/event types, optional model override, and
  analyst context such as report excerpts, behavior notes, field constraints,
  IOCs, and false-positive notes.
- Generated output is still validated structurally and stored as a detection
  version with generation metadata.

## Verification

- Docker Compose config validation passed.
- Backend source compile check passed.
- Focused detection generator and detection-feed unit tests passed.
- Focused AI detection-generation test passed with a mocked provider.
- Frontend production build passed.
- Frontend lint passed.
- Live deterministic detection-generation route smoke test passed.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.5.9
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Published v2.5 article: https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e
- 1200km article mirror: https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.5.9.md`
