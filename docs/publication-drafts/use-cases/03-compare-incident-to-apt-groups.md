# Compare An Incident To Known APT Groups: A Practical AdversaryGraph Workflow

**Subtitle:** Which known groups have the strongest TTP overlap with this incident?

## Introduction

Many CTI and detection engineering tasks fail because the work stops at reading a report. The useful output is not the report itself. The useful output is a reviewed set of behaviors, observables, actor hypotheses, detection priorities, and evidence that another analyst can verify.

This article shows one practical AdversaryGraph workflow: **Compare An Incident To Known APT Groups**.

AdversaryGraph is a self-hosted AI-assisted CTI platform that connects threat reports, MITRE ATT&CK techniques, actor context, IOC enrichment, and detection engineering handoff. The goal is not to replace analyst judgment. The goal is to remove repetitive mechanical work and make the review process clearer.

## The Analyst Problem

Which known groups have the strongest TTP overlap with this incident?

Without a structured workflow, this usually becomes manual copy-paste work: reading the source, searching ATT&CK, comparing actors, collecting observables, and writing the same summary again for a customer, SOC team, or detection engineer.

## The AdversaryGraph Workflow

1. **Extract TTPs from the incident report.**
2. **Run group comparison against ATT&CK actor profiles.**
3. **Inspect Jaccard similarity and shared technique lists.**
4. **Open matching actor pages to review aliases, campaigns, and evidence.**
5. **Record the result as a hypothesis, not attribution.**


## What The Analyst Gets

Ranked actor candidates for hypothesis generation and investigation prioritization.

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
