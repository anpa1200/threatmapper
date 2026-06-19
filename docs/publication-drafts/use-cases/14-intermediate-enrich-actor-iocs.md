# Enrich Actor IOCs: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Add current observable context to one actor profile.

## Why This Use Case Matters

Add current observable context to one actor profile. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Workflow

1. **Open actor profile and IOCs tab.**
2. **Sync ThreatFox/OTX/Malpedia or custom feeds.**
3. **Review IOC source, last seen, malware, and confidence.**
4. **Open enrichment for high-value observables.**
5. **Export CSV if the SOC needs a watchlist.**


## Expected Output

Source-labeled actor IOC context.

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
