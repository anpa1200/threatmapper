# Mapping Review Rubric

Use this rubric to review extracted ATT&CK mappings.

## Required Fields

Each accepted mapping should have:

- ATT&CK ID.
- Technique name.
- Tactic.
- Evidence text or source section.
- Confidence.
- Review status.
- ATT&CK version.

## Acceptance Criteria

Accept a mapping when:

- The report describes behavior matching the ATT&CK technique.
- The evidence is specific enough to distinguish the technique.
- The mapping does not rely only on actor name, tool reputation, or assumptions.
- The selected sub-technique is supported by the evidence.

Reject a mapping when:

- The report only says the actor is known to use the behavior elsewhere.
- The evidence supports a different technique.
- The mapping is based only on a tool name without described behavior.
- The technique is speculative.

Mark `needs-evidence` when:

- The mapping is plausible but source text is incomplete.
- The report implies behavior but lacks procedure detail.
- A secondary source is needed.

## Confidence Guidance

| Confidence | Meaning |
|---|---|
| High | Direct procedure-level evidence supports the mapping |
| Medium | Evidence supports the behavior, but technique specificity is debatable |
| Low | Weak evidence, inferred behavior, or incomplete source context |

## Attribution Guardrail

ATT&CK overlap can support investigation prioritization, but it is not attribution proof. Final reports should separate:

- Observed behavior.
- Reported actor claims.
- Analyst assessment.
- Unknowns and gaps.
