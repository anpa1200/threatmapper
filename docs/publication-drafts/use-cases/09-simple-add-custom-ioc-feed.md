# Add A Custom IOC Feed: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Connect a private or custom IOC feed.

## Why This Use Case Matters

Connect a private or custom IOC feed. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

A customer sends a short CSV of indicators from their incident response team, and the analyst needs to import it without mixing it with public feed data.

## Workflow

1. **Open IOC Library source panel and add a JSON, CSV, or TXT feed with a clear label.**
2. **Run sync and filter by the source label to verify import.**


## Expected Output

Private or custom observables stored with source context.

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
