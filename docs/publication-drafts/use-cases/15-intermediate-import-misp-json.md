# Import MISP JSON: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Bring MISP event or attribute exports into IOC Library.

## Why This Use Case Matters

Bring MISP event or attribute exports into IOC Library. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Workflow

1. **Create or expose a MISP JSON export URL.**
2. **Open IOC Library source panel and connect the MISP source.**
3. **Sync and filter by the MISP source label.**
4. **Review imported observables and tags.**
5. **Enrich or export only approved data.**


## Expected Output

MISP-backed IOC records searchable in AdversaryGraph.

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
