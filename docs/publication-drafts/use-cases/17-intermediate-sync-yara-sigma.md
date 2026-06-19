# Sync YARA And Sigma Feeds: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Connect detection-rule context to IOCs and malware.

## Why This Use Case Matters

Connect detection-rule context to IOCs and malware. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

A malware analyst finds a suspicious hash and wants to know whether public or internal YARA/Sigma rules already describe related behavior.

## Workflow

1. **Add YARA/Sigma feed sources.**
2. **Run rule-feed sync.**
3. **Open IOC or malware enrichment.**
4. **Review matching rule names, tags, and references.**
5. **Use rule context as detection research input.**


## Expected Output

Detection content leads tied to IOC/malware context.

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
