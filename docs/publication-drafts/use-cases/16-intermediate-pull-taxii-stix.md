# Pull TAXII Or Import STIX: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Exchange structured intelligence with CTI platforms.

## Why This Use Case Matters

Exchange structured intelligence with CTI platforms. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Workflow

1. **Prepare TAXII collection URL or STIX bundle.**
2. **Import/pull the data in IOC Library.**
3. **Review imported indicators and observed-data records.**
4. **Filter by source and actor where possible.**
5. **Export STIX when sharing reviewed IOC subsets.**


## Expected Output

Structured STIX/TAXII intelligence connected to IOC workflows.

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
