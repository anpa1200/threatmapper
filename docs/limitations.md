# Limitations

ThreatMapper is designed to assist CTI analysts. It does not replace analyst judgment.

## ATT&CK Mapping

- The model can produce false positives and false negatives.
- A tool mention does not always justify a technique mapping.
- A broad technique may need a more specific sub-technique.
- Some reports do not provide enough detail for precise mapping.
- ATT&CK version changes can alter names, tactics, or relationships.

## Attribution

ThreatMapper does not prove attribution.

Group and campaign comparison uses TTP overlap. TTP overlap can result from:

- Shared tools.
- Common tradecraft.
- Reporting bias.
- Incomplete source coverage.
- Reused infrastructure.
- Coincidental overlap.

Use similarity as a lead, not a conclusion.

## Detection Engineering

Generated detection content is draft material.

Before production use:

- Confirm telemetry exists.
- Check false-positive conditions.
- Validate in a lab or historical dataset.
- Add triage guidance.
- Review with detection engineering owners.

## Privacy

Docker mode sends report content to the configured LLM provider. Use a private provider or local gateway if report content cannot leave the environment.

## Deployment

The default Compose profile is intended for local and controlled self-hosted use. It is not a hardened public SaaS configuration.
