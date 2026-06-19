# Open One Actor Profile: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Review the core context for one ATT&CK group or actor.

## Why This Use Case Matters

Review the core context for one ATT&CK group or actor. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

A CTI analyst is asked during a standup what APT29 is known for and needs a fast actor summary with aliases, techniques, reports, and observable context.

## Workflow

1. **Open ATT&CK Group Library and search the actor name, ID, or alias.**
2. **Review description, aliases, techniques, reports, IOCs, and tactic coverage.**


## Expected Output

Actor context ready for a note, briefing, or investigation pivot.

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
