# Search The IOC Library: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Find whether an observable already exists in local or synced intelligence.

## Why This Use Case Matters

Find whether an observable already exists in local or synced intelligence. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

An incident responder finds an IP address in proxy logs and needs to know whether it already exists in synced ThreatFox, MISP, OTX, or private customer feeds.

## Workflow

1. **Open IOC Library and search the indicator, malware name, campaign, actor, or source.**
2. **Filter by type/source/group and open enrichment for the most relevant result.**


## Expected Output

Fast lookup across stored public and private observables.

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
