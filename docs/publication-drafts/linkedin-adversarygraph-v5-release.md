# LinkedIn Post Draft - AdversaryGraph v5.0

I published the AdversaryGraph v5.0 release article:

https://medium.com/@1200km/adversarygraph-v5-0-from-cti-mapping-to-attack-simulation-and-siem-validation-21873b2a6c39

AdversaryGraph started as a CTI-to-detection workbench for mapping reports, IOCs, malware findings, and operational telemetry to MITRE ATT&CK. Version 5.0 adds the next step: detection validation.

New in v5.0: Attack Simulation.

The goal is simple: select a TTP, run a controlled validation workflow, inspect the telemetry, and forward the evidence to a SIEM for parser, rule, dashboard, and correlation testing.

Key capabilities:

- TTP-first Attack Simulation workflow from an ATT&CK-style matrix.
- Dedicated simulation pages with scenario description, telemetry sources, detection focus, and validation gaps.
- Docker-based lab web target that receives real HTTP attack-flow requests and writes target-side logs.
- Real-time log view for attacked-server access, auth, security/WAF, error, endpoint, JSONL, and merged telemetry streams.
- SIEM forwarding with saved non-secret destinations, source selection, payload format selection, route handling, and auth options.
- AI Attack Assistant for selected-TTP, actor-oriented, and Challenge Me scenarios.
- Named coherent kill-chain templates instead of random disconnected events.
- Multi-source telemetry drills across web, WAF, DNS, proxy, firewall, Windows Security, Sysmon, EDR, and endpoint-shaped event patterns.
- Attack-chain graph and Explain Attack panel so the analyst can understand the phases, expected detections, and validation logic.

This is defensive validation tooling. It does not execute malware, exploit arbitrary targets, or run unrestricted commands. The web execution path is scoped to the approved lab target, and AI-generated telemetry is for SIEM validation and detection engineering exercises.

Why this matters:

ATT&CK mapping is useful, but mapping alone does not prove detection coverage. Detection engineering needs evidence: what telemetry was produced, where it landed, what rule should trigger, what did not trigger, and what gaps remain. AdversaryGraph v5.0 is built around that workflow.

Links:

- Release article: https://medium.com/@1200km/adversarygraph-v5-0-from-cti-mapping-to-attack-simulation-and-siem-validation-21873b2a6c39
- Project: https://1200km.com/adversarygraph/
- Documentation: https://1200km.com/adversarygraph-docs/
- GitHub: https://github.com/anpa1200/adversarygraph
- Live ATT&CK workspace: https://1200km.com/threat-matrix/

#ThreatIntelligence #DetectionEngineering #MITREATTACK #SIEM #SOC #CyberSecurity #DFIR #ThreatHunting #AdversarySimulation #CTI
