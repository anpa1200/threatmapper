# User Guide

ThreatMapper is built around a defensive CTI workflow:

```text
report -> ATT&CK mapping candidates -> analyst review -> actor/campaign comparison -> detection gaps -> exports
```

## Core Concepts

| Concept | Meaning |
|---|---|
| Technique | MITRE ATT&CK technique or sub-technique ID such as `T1566.001` |
| Evidence | The report text that supports a mapping |
| Confidence | Extraction confidence from the model plus analyst judgment |
| Similarity | Jaccard overlap between selected TTPs and a known group/campaign profile |
| Detection gap | A mapped behavior without sufficient local telemetry, detection, or validation |

## Public Web Workspace

Use <https://1200km.com/threat-matrix/> for:

- ATT&CK exploration.
- Manual layer creation.
- Group overlays.
- Group and campaign comparison.
- Coverage-gap review.
- Browser-generated exports.

Do not upload private reports to public demos.

## Docker Workspace

Use the Docker deployment for:

- Private report analysis.
- PostgreSQL-backed report history.
- Configured LLM extraction.
- Stored analyses and exports.
- API-driven workflows.

## Analyst Workflow

### 1. Start With a Question

Examples:

- Which ATT&CK techniques appear in this public report?
- Which known groups share TTP overlap with this report?
- Which mapped behaviors lack detection coverage?
- Which telemetry sources are required before writing detections?

### 2. Ingest or Paste a Report

Supported inputs:

- Plain text.
- PDF.
- DOCX.

ThreatMapper extracts candidate ATT&CK mappings. These are suggestions, not final intelligence.

### 3. Review Technique Evidence

For every mapping, check:

- Does the evidence show behavior, or only a tool name?
- Is the technique too broad?
- Is a sub-technique more accurate?
- Is the mapping based on actor attribution rather than observed behavior?
- Is the confidence justified?

### 4. Compare With Groups and Campaigns

Similarity is an investigation lead only. It is not attribution proof.

Use comparison to answer:

- Which known profiles share behaviors?
- Which techniques are common commodity behaviors?
- Which overlaps are distinctive enough to investigate?
- Which expected techniques are missing from the report?

### 5. Build Detection Gaps

For each accepted technique, record:

- Required telemetry.
- Current detection status.
- Candidate logic.
- Validation environment.
- Triage guidance.

### 6. Export

Use exports for:

- ATT&CK Navigator review.
- Analyst handoff.
- Detection backlog planning.
- Report appendix material.

Generated detections or summaries must be reviewed before use.

## Review Rules

- ATT&CK is not attribution evidence.
- Tool names do not automatically imply techniques.
- LLM output is untrusted until reviewed.
- Similarity scores should be explained in prose.
- Low-confidence mappings should remain in a backlog, not in final findings.
