# Open Troubleshooting For An Error: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Move from a popup error to practical remediation.

## Why This Use Case Matters

Move from a popup error to practical remediation. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Workflow

1. **Click Open troubleshooting in the error popup.**
2. **Follow the relevant fix and use Recheck to confirm resolution.**


## Expected Output

Fast path from error to fix verification.

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
