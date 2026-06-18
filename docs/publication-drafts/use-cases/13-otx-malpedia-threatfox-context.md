# Pull Intelligence From OTX, Malpedia, And ThreatFox: A Practical AdversaryGraph Workflow

**Subtitle:** How can open intelligence enrich actors and observables?

## Introduction

Many CTI and detection engineering tasks fail because the work stops at reading a report. The useful output is not the report itself. The useful output is a reviewed set of behaviors, observables, actor hypotheses, detection priorities, and evidence that another analyst can verify.

This article shows one practical AdversaryGraph workflow: **Pull Intelligence From OTX, Malpedia, And ThreatFox**.

AdversaryGraph is a self-hosted AI-assisted CTI platform that connects threat reports, MITRE ATT&CK techniques, actor context, IOC enrichment, and detection engineering handoff. The goal is not to replace analyst judgment. The goal is to remove repetitive mechanical work and make the review process clearer.

## The Analyst Problem

How can open intelligence enrich actors and observables?

Without a structured workflow, this usually becomes manual copy-paste work: reading the source, searching ATT&CK, comparing actors, collecting observables, and writing the same summary again for a customer, SOC team, or detection engineer.

## The AdversaryGraph Workflow

1. **Configure API keys where required.**
2. **Use Reference Sync or actor enrichment.**
3. **Pull source-backed malware, pulse, and IOC context.**
4. **Normalize aliases and malware family names.**
5. **Review source timestamps and confidence.**


## What The Analyst Gets

Enriched actor and IOC evidence from external open intelligence sources.

## Why This Matters

This workflow creates a clean handoff between CTI and operations. The analyst can show what was extracted, why it was mapped, which evidence supports it, and what should happen next.

## Review Discipline

AdversaryGraph should be used as an analyst accelerator, not an attribution oracle. TTP overlap, enrichment hits, and actor links are signals. They become useful only after evidence review, confidence calibration, and human judgment.

Before publishing or handing off the result:

- Confirm that every accepted TTP has evidence.
- Separate strong findings from weak hypotheses.
- Keep rejected or uncertain mappings visible for auditability.
- Export reviewed results, not raw model output.

## Practical Output

A finished workflow can produce a Navigator layer, structured JSON, IOC records, actor notes, detection backlog items, and a PDF report. That makes the result reusable by CTI analysts, SOC analysts, detection engineers, and incident responders.

## Closing

The main value of AdversaryGraph is repeatability. Instead of treating every report as a blank page, the analyst gets a structured path from raw intelligence to ATT&CK mapping, enrichment, comparison, and operational handoff.

**Project:** https://github.com/anpa1200/adversarygraph  
**Docs:** https://1200km.com/adversarygraph-docs/  
**Use cases:** https://1200km.com/adversarygraph/use-cases.html
