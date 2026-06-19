# Map A Report To ATT&CK: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Turn one report into reviewed ATT&CK techniques.

## Why This Use Case Matters

Turn one report into reviewed ATT&CK techniques. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Workflow

1. **Load PDF/DOCX/TXT or paste text into AI Analysis.**
2. **Choose provider/domain and run extraction.**
3. **Review evidence for every TTP and set review status.**
4. **Inject accepted TTPs into Navigator.**
5. **Export JSON, layer, or PDF.**


## Expected Output

Reviewed TTP set with evidence and exportable layer/report.

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
