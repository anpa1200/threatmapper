# Defense: Create Detection Content From CTI: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Turn CTI findings into detection content candidates.

## Why This Use Case Matters

Turn CTI findings into detection content candidates. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Workflow

1. **Analyze source report and accept validated TTPs.**
2. **Extract IOCs and enrich high-value observables.**
3. **Open TTP detail panels and detection references.**
4. **Sync Sigma/YARA feeds and search for related rules.**
5. **Map each TTP to telemetry requirements.**
6. **Write candidate logic or Sigma/SIEM task notes.**
7. **Mark expected false positives and tuning inputs.**
8. **Create backlog items in Pipeline/Operations.**
9. **Export report, layer, and IOC appendix.**
10. **Validate detections with test data or replay where possible.**


## Expected Output

Detection content package traceable from CTI evidence to engineering tasks.

## Analyst Review Standard

- Keep source evidence and source labels attached.
- Mark uncertain findings as `needs-evidence` instead of forcing a conclusion.
- Do not treat TTP similarity as attribution by itself.
- Use enrichment as context, not as an automatic decision.
- Export only reviewed findings.

## Where This Fits

This use case can support CTI production, SOC triage, threat hunting, detection engineering, customer reporting, or platform validation depending on the workflow level.

**Project:** https://github.com/anpa1200/adversarygraph  
**Docs:** https://1200km.com/adversarygraph-docs/  
**Use cases:** https://1200km.com/adversarygraph/use-cases.html
