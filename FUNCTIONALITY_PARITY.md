# ThreatMapper Functionality Parity

## Product rule

The Docker platform is the superset product: ThreatMapper Web analyst workflow plus
private/server capabilities and AI functions.

## Shared workflow

Both products provide ATT&CK matrix exploration, actor profiles, actor overlays, TTP
similarity, group comparison, correlated CTI/IR reports, ecosystem research links,
detection guidance, mitigation guidance, threat-hunting hypotheses, hunt-plan export,
coverage import and backlog export, evidence/maturity assessments, investigation
workspaces, shareable entity links, and investigation reports.

## Docker-only capabilities

- Persistent operational intelligence workbench
- Campaign/investigation evidence graphs and timelines
- Analyst-reviewed report intake
- Tracked-actor behavior change logs
- Detection engineering lifecycle management
- AI-assisted PDF/DOCX/text report analysis
- LLM technique assistant
- Private stored report sessions
- MITRE campaign ingestion and comparison
- PostgreSQL-backed saved layers
- Server-side PDF exports and APIs
- Automated ATT&CK and ATLAS synchronization
- Self-hosted/private deployment

## Current architecture note

ThreatMapper Docker now ingests MITRE ATLAS as a first-class `atlas` domain in
PostgreSQL beside Enterprise, Mobile, and ICS ATT&CK. ATLAS currently contributes
matrix, tactic, technique, and sub-technique objects; APT groups and campaigns remain
ATT&CK datasets because the upstream ATLAS bundle does not publish intrusion-set or
campaign profiles.
