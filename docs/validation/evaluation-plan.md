# Validation and Evaluation Plan

This document defines how ThreatMapper mapping quality should be evaluated before resubmission to curated security lists.

## Goal

Measure whether ThreatMapper produces useful ATT&CK mapping candidates that reduce analyst triage time without hiding uncertainty.

## Dataset

Use public, TLP:CLEAR reports only.

Initial target:

- 10 public reports.
- At least 5 vendors or public agencies.
- At least 3 different intrusion sets or campaigns.
- Reports with enough procedural detail to support ATT&CK mapping.

## Ground Truth

For each report:

1. A human analyst creates expected mappings.
2. Each expected mapping must include evidence text.
3. Ambiguous mappings are marked as `uncertain`, not forced into ground truth.
4. ATT&CK version is recorded.

## Metrics

| Metric | Definition |
|---|---|
| Candidate precision | Accepted candidate mappings / total candidate mappings |
| Candidate recall | Accepted candidate mappings / expected mappings |
| Evidence coverage | Candidate mappings with supporting source text / total candidate mappings |
| Review burden | Rejected plus uncertain mappings / total candidate mappings |
| Export correctness | JSON, Navigator, CSV, and Markdown exports match reviewed mappings |

## Review Labels

| Label | Meaning |
|---|---|
| accepted | Evidence supports the mapping |
| rejected | Evidence does not support the mapping |
| needs-evidence | Mapping may be valid but evidence is insufficient |
| duplicate | Mapping repeats another accepted mapping |
| too-broad | A sub-technique is more accurate |
| too-specific | Evidence supports only the parent technique |

## Current Status

The repo includes a demo dataset and sample outputs. A full multi-report evaluation should be completed before resubmitting ThreatMapper to curated awesome lists.
