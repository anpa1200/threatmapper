# AdversaryGraph Demo Dataset

This dataset gives reviewers deterministic input for evaluating report mapping, IOC extraction, asset-surface analysis, and SIEM telemetry handling without using private data.

## Files

| File | Purpose |
|---|---|
| `sample-report.md` | Public-style CTI report excerpt with ATT&CK behaviors and IOCs |
| `firewall.log` | Firewall/proxy-like egress and scan events |
| `edr.jsonl` | Endpoint process, file, and credential-access telemetry |
| `iocs.csv` | IOC import sample |
| `asset-inventory.csv` | Asset Surface inventory sample |
| `expected-techniques.json` | Expected ATT&CK technique candidates |
| `expected-iocs.json` | Expected IOC extraction output |
| `expected-navigator-layer.json` | Expected Navigator-style layer |
| `expected-report.md` | Expected analyst summary shape |

## Review Flow

1. Upload or paste `sample-report.md` into AI Analysis.
2. Import `iocs.csv` into IOC workflows or paste values into IOC Investigation.
3. Upload `asset-inventory.csv` into Asset Surface.
4. Forward or ingest `firewall.log` and `edr.jsonl` into a test SIEM/parser.
5. Compare the result to the expected JSON files.

Expected outputs are not ground truth for every model response. They are a stable baseline for checking that the platform extracts the obvious behaviors, keeps evidence visible, and avoids treating AI output as final attribution.
