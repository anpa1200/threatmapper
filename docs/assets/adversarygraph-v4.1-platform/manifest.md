# AdversaryGraph v4.1 Platform Screenshots

Captured from `http://localhost:3000` on 2026-06-27 at `1920x1200`.

Validation metadata is stored in [`validation.json`](validation.json).

| File | Module | Description |
|---|---|---|
| `01-discover-launchers.png` | Discover dashboard | Updated first-screen workflow launchers for actor investigation, AI report analysis, malware analysis, asset-surface mapping, behavior comparison, coverage review, debug workflow, and unpacking. |
| `02-asset-surface-analysis.png` | Asset Surface analysis | Baseline asset-inventory analysis with exposure counts, risk scoring, executive summary, ATT&CK candidates, entry points, priority actions, and validation guidance. |
| `03-asset-surface-history.png` | Asset Surface saved cases | Saved Asset Surface cases after running the sample inventory, including reload/delete controls and high-level counts. |
| `04-asset-surface-white-matrix.png` | Navigator white asset layer | ATT&CK Navigator view with inventory-derived TTP candidates loaded as a white comparison layer distinct from manual selections. |

## Capture Notes

- The sample Asset Surface run used the built-in example inventory.
- AI enrichment was disabled for the screenshot run so the baseline deterministic
  scoring path is reproducible without external model availability.
- Global self-test popups were closed before capture so screenshots show the
  target workflow state.
