# AdversaryGraph v3.0.0 Release Summary

AdversaryGraph v3.0.0 is the investigation workbench release.

The release focuses on turning a single IOC, URL, hash, suspicious artifact,
log excerpt, or PCAP-derived telemetry export into a defensible analyst
workflow. The platform now helps collect evidence, rank pivots, explain graph
relationships, preserve investigation history, and prepare report-ready output.

## Operator Value

- Start from one IOC or suspicious artifact and expand source-backed
  relationships through Tier 1, Tier 2, and Tier 3 pivots.
- Focus the graph on any node to see its direct connected neighborhood.
- Open every graph node as a detail page.
- Reinvestigate observable nodes directly from the graph.
- Rank evidence and next-best pivots instead of manually reading noisy provider
  output.
- Review timeline and source-conflict summaries before writing conclusions.
- Save previous IOC investigations and delete stale sessions when needed.
- Analyze logs, PCAP-derived text, command traces, scripts, and investigation
  notes with AI-assisted IOC/TTP extraction.
- Send extracted TTPs to Navigator for layer comparison and coverage review.

## Main Workflows

1. IOC Investigation
2. Relationship graph pivoting
3. Evidence ranking and next-best pivots
4. Saved investigation history
5. AI log and PCAP analysis
6. ATT&CK Navigator handoff
7. Actor/TTP lead review with attribution caveats
8. Analyst-ready reporting

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v3.0.0
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Capabilities: https://1200km.com/adversarygraph-docs/capabilities/
- Use cases: https://1200km.com/adversarygraph/use-cases.html
- Log-to-report article: https://1200km.com/articles/adversarygraph-from-log-to-report-ioc-investigation.html
- Article draft: `docs/publication-drafts/adversarygraph-v3-ioc-investigation-ai-log-pcap-analysis.md`
- Workflow draft: `docs/publication-drafts/medium-adversarygraph-from-log-to-report-ioc-investigation.md`
- Detailed notes: `docs/release-notes/v3.0.0.md`
