# Compare Two Reports: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Assess whether two reports describe related activity.

## Why This Use Case Matters

Assess whether two reports describe related activity. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

Two public reports mention similar tooling and infrastructure, and the analyst needs to decide whether they describe the same campaign or only common tradecraft.

## Workflow

1. **Analyze and store both reports.**
2. **Open report comparison.**
3. **Compare shared and unique TTPs, IOCs, and actor hints.**
4. **Separate generic overlap from distinctive behavior.**
5. **Export the comparison summary.**


## Expected Output

Relationship assessment between reports.

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
