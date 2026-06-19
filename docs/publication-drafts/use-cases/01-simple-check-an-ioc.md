# Check One IOC: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Check whether one IP, domain, URL, or hash has useful enrichment context.

## Why This Use Case Matters

Check whether one IP, domain, URL, or hash has useful enrichment context. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Workflow

1. **Open VirusTotal Lookup or IOC Library Enrichment.**
2. **Submit the indicator and review reputation, tags, relationships, and possible actor/TTP links.**


## Expected Output

Quick IOC context for triage or hunting seed.

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
