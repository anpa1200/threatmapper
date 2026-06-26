# AdversaryGraph v4.0.0 Release Summary

AdversaryGraph v4.0.0 is the Malware Analysis platform release. The version
marks full operational readiness of the integrated MalwareGraph module and
the surrounding intelligence infrastructure that makes every finding actionable.

## Release Focus

- The Malware Analysis module graduates from a UI/API development milestone
  to a fully documented, tested analyst workflow with 24 practical use cases.
- Every extracted hash, IP, domain, URL, ATT&CK technique, family lead, and
  IOC is clickable and routes into existing AdversaryGraph views: IOC
  Intelligence, ATT&CK Navigator, APT Library, Compare Groups, Detection Studio,
  and Knowledge Library.
- A 57-test suite validates all proxy routes, MalwareGraphClient error paths
  (timeout/connection error/invalid JSON/4xx/5xx), and the standalone service
  API — the first comprehensive backend test coverage for the module.
- The Knowledge Library adds a searchable, filtered, markdown-rendered
  intelligence article repository seeded with 39 NVIDIA sector intelligence
  documents (CVEs, PSIRT analyses, threat actor profiles, vendor reports,
  research, and strategy).
- NVIDIA Sector Packs now deep-link to every relevant AdversaryGraph tool
  directly from technique IDs, actor names, IOC types, and CVE IDs.
- Dynamic Analysis now includes an AI feedback loop that steps function evidence,
  reruns AI review, and records evidence gained, validation gaps, next actions,
  and confidence by iteration.
- The debugger workspace now has an IDA-style AI function view with step/run
  controls, function purpose summaries, whole-malware debug summary, and
  normal/suspicious/malicious function tags.

## What Changed Since v3.2.0

| Area | v3.2.0 | v4.0.0 |
|---|---|---|
| Malware Analysis API | 25 routes live, undocumented | 25 routes with full analyst guide and 24 use cases |
| Test coverage | 1 unit test (timeout path) | 57 tests (unit + integration + standalone) |
| Knowledge base | Not present | 39 articles, full CRUD API, markdown rendering |
| Sector Packs deep-links | Static text | Navigator/APT/IOC/Knowledge clickthrough |
| Article / publication draft | v3 IOC investigation | v4 malware analysis walkthrough |

## Links

- Malware Analysis Guide: `docs/malware-analysis-guide.md`
- Release Article Draft: `docs/publication-drafts/adversarygraph-v4-malware-analysis.md`
- Malware Analysis Module: `docs/malware-analysis-module.md`
- Malware Analysis Architecture: `docs/malware-analysis-architecture.md`
- Detailed notes: `docs/release-notes/v4.0.0.md`
