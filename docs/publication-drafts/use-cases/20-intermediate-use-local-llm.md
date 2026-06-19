# Use A Local LLM For Private Reports: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Analyze sensitive content without public LLM routing.

## Why This Use Case Matters

Analyze sensitive content without public LLM routing. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

A customer report contains sensitive incident details, so the analyst must run extraction through a private local LLM gateway instead of a public API.

## Workflow

1. **Configure local/private LLM gateway in deployment env.**
2. **Run selftest and confirm provider is reachable.**
3. **Choose local provider in AI Analysis.**
4. **Analyze the report and review mappings.**
5. **Export only reviewed findings.**


## Expected Output

Private report extraction with controlled model routing.

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
