# AdversaryGraph + OpenCTI: Building Symmetric CTI Sync For IOCs, Reports, Labels, And Analyst Workflow

Threat intelligence platforms are strongest when they are connected.

OpenCTI is excellent as a CTI knowledge graph and intelligence management platform. AdversaryGraph is built for a slightly different part of the analyst workflow: taking reports, IOCs, actor context, ATT&CK techniques, sector relevance, enrichment results, and detection engineering handoff, then making that information operational.

Until now, AdversaryGraph supported OpenCTI-style handoff mainly through STIX export.

That was useful, but incomplete.

The new integration adds a direct OpenCTI sync workflow:

- pull indicators from OpenCTI into AdversaryGraph;
- pull observables from OpenCTI into the local IOC Library;
- preserve OpenCTI labels and source context;
- pull OpenCTI reports into the AdversaryGraph report history;
- push local AdversaryGraph IOCs back to OpenCTI as indicators;
- push completed AdversaryGraph reports back to OpenCTI;
- run bidirectional sync from the Feeds Management page.

The goal is not to replace OpenCTI.

The goal is to connect OpenCTI with the practical analyst workflow inside AdversaryGraph.

Project:

https://github.com/anpa1200/adversarygraph

Documentation:

https://1200km.com/adversarygraph-docs/

OpenCTI:

https://www.opencti.io/

## Table Of Contents

- [Why This Integration Matters](#why-this-integration-matters)
- [What Gets Synchronized](#what-gets-synchronized)
- [Architecture](#architecture)
- [Installation](#installation)
- [OpenCTI Configuration](#opencti-configuration)
- [Using The Integration In The UI](#using-the-integration-in-the-ui)
- [API Workflow](#api-workflow)
- [Pull From OpenCTI](#pull-from-opencti)
- [Push To OpenCTI](#push-to-opencti)
- [Bidirectional Sync](#bidirectional-sync)
- [How The Mapping Works](#how-the-mapping-works)
- [Operational Use Case](#operational-use-case)
- [Security Notes](#security-notes)
- [Limitations](#limitations)
- [Recommended Workflow](#recommended-workflow)
- [Final Thoughts](#final-thoughts)
- [Follow My Work](#follow-my-work)

## Why This Integration Matters

In real CTI work, there is rarely one system that does everything.

A team may use OpenCTI as the central knowledge graph.

The same team may also need:

- ATT&CK matrix review;
- report-to-TTP extraction;
- IOC enrichment;
- actor and campaign comparison;
- sector-specific threat prioritization;
- detection engineering handoff;
- PDF, Markdown, STIX, and Navigator exports;
- analyst review states for mapped techniques.

AdversaryGraph focuses on that operational layer.

The OpenCTI integration makes the workflow two-way:

```text
OpenCTI -> AdversaryGraph -> enrichment / analysis / comparison / reporting -> OpenCTI
```

This matters because CTI is not only about storing objects.

It is about improving the quality, context, and usefulness of those objects.

## What Gets Synchronized

The integration supports three main object families.

### 1. Indicators And Observables

AdversaryGraph can pull OpenCTI indicators and cyber observables into the local IOC Library.

Supported IOC types include:

- IPv4;
- IPv6;
- domain;
- URL;
- MD5;
- SHA1;
- SHA256;
- IP with port, normalized where possible.

OpenCTI labels are preserved as IOC tags.

Source URLs and object URLs are preserved when available.

ATT&CK technique IDs found in OpenCTI metadata, descriptions, labels, or report context are extracted and stored as IOC-to-TTP context.

### 2. Reports

OpenCTI reports are imported into AdversaryGraph as completed report records.

That makes them available for:

- report history;
- later comparison;
- local review;
- TTP extraction context;
- analyst reporting.

If OpenCTI report objects include indicators or observables, AdversaryGraph imports those observables with the report context attached.

### 3. Local AdversaryGraph Records

AdversaryGraph can push local records back to OpenCTI:

- local IOC Library records become OpenCTI indicators;
- completed AdversaryGraph analysis reports become OpenCTI reports;
- labels/tags and basic source metadata are included;
- ATT&CK technique IDs are preserved in AdversaryGraph metadata fields.

The sync is additive/update-oriented.

It does not delete OpenCTI data.

## Architecture

The integration is implemented inside the AdversaryGraph Docker stack.

The relevant components are:

- React / Vite frontend;
- FastAPI backend;
- PostgreSQL local database;
- IOC Library;
- Feeds Management page;
- OpenCTI GraphQL API.

OpenCTI remains external.

AdversaryGraph connects to it using:

```text
OPENCTI_URL
OPENCTI_TOKEN
```

The backend talks to OpenCTI through its GraphQL API and stores synchronized objects in the local AdversaryGraph database.

The local database remains important. It lets analysts enrich, compare, review, and report without turning every working change into an immediate upstream change.

## Installation

Clone the project:

```bash
git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
```

Create the environment file:

```bash
cp .env.example .env
```

Start the platform:

```bash
docker compose up -d --build
```

Open the UI:

```text
http://localhost:3000
```

Open the API health endpoint:

```bash
curl http://localhost:8000/api/health
```

## OpenCTI Configuration

Edit `.env` and add your OpenCTI connection values:

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=your_opencti_token
OPENCTI_SYNC_LIMIT=500
OPENCTI_VERIFY_TLS=true
```

Then restart the stack:

```bash
docker compose up -d --build
```

The OpenCTI token should allow:

- reading indicators;
- reading cyber observables;
- reading labels;
- reading reports;
- creating or updating indicators;
- creating or updating reports.

You do not need to expose this token to the frontend.

It stays in the backend container environment.

## Using The Integration In The UI

Open:

```text
Feeds Management
```

Then find:

```text
OpenCTI symmetric sync
```

The UI provides four actions.

### Check OpenCTI

This validates:

- `OPENCTI_URL`;
- `OPENCTI_TOKEN`;
- OpenCTI GraphQL reachability;
- OpenCTI version where available.

Use this first.

If it fails, the global error popup shows the problem and links to troubleshooting.

### Pull From OpenCTI

This imports OpenCTI data into AdversaryGraph:

- indicators;
- cyber observables;
- labels;
- reports;
- report-linked observables where available.

Use this when OpenCTI is the source of existing intelligence.

### Push To OpenCTI

This sends local AdversaryGraph records to OpenCTI:

- local IOC Library records as OpenCTI indicators;
- completed AdversaryGraph reports as OpenCTI reports.

Use this after analysis, enrichment, review, or report creation.

### Bidirectional Sync

This runs:

```text
pull first -> push second
```

That order is intentional.

It reduces the chance of pushing stale local context before the local database has seen the latest OpenCTI objects.

## API Workflow

The same operations are available through the API.

### Status

```bash
curl http://localhost:8000/api/ioc/opencti/status
```

### Pull

```bash
curl -X POST "http://localhost:8000/api/ioc/opencti/pull?limit=500&domain=enterprise-attack"
```

### Push

```bash
curl -X POST "http://localhost:8000/api/ioc/opencti/push?limit=500&include_reports=true"
```

### Bidirectional Sync

```bash
curl -X POST "http://localhost:8000/api/ioc/opencti/sync?limit=500&domain=enterprise-attack&include_reports=true"
```

The response includes counts and errors.

Example structure:

```json
{
  "source": "opencti",
  "direction": "pull",
  "indicators_seen": 120,
  "observables_seen": 300,
  "reports_seen": 40,
  "reports_imported": 12,
  "inserted": 80,
  "updated": 340,
  "actor_links": 5,
  "ttp_enriched": 22,
  "errors": []
}
```

For bidirectional sync, the response contains separate `pull` and `push` results.

## Pull From OpenCTI

Pull is useful when OpenCTI already contains intelligence from:

- commercial feeds;
- internal reports;
- manual analyst curation;
- MISP connectors;
- TAXII feeds;
- incident response reporting;
- malware analysis.

After pulling into AdversaryGraph, the analyst can:

- search the IOC Library;
- filter by IOC type;
- filter by source;
- filter by actor or attacker;
- open IOC enrichment;
- map IOCs to ATT&CK TTPs;
- compare TTPs with known actors;
- add TTPs to the matrix;
- generate reports.

OpenCTI remains the knowledge graph.

AdversaryGraph becomes the analysis and operationalization workspace.

## Push To OpenCTI

Push is useful after AdversaryGraph creates new value.

For example:

1. An analyst uploads a DFIR report.
2. AdversaryGraph extracts candidate TTPs.
3. The analyst reviews the mappings.
4. The IOC Library enriches observables with local and external context.
5. The analyst generates a report.
6. The final IOCs and report are pushed back to OpenCTI.

That creates a clean loop:

```text
intelligence -> analysis -> enrichment -> report -> CTI knowledge graph
```

## Bidirectional Sync

Bidirectional sync is for teams that use both tools daily.

Example:

- OpenCTI receives external feed data and analyst-curated reports.
- AdversaryGraph pulls that data.
- Analysts enrich and review it.
- AdversaryGraph pushes improved local context back.

This makes the tools complementary instead of isolated.

## How The Mapping Works

The integration maps OpenCTI data into AdversaryGraph in a conservative way.

### OpenCTI Indicator To AdversaryGraph IOC

OpenCTI indicator patterns are parsed into IOC values.

Example:

```text
[domain-name:value = 'evil.example']
```

becomes:

```text
type: domain
value: evil.example
```

Supported STIX pattern types include:

- `domain-name:value`;
- `url:value`;
- `ipv4-addr:value`;
- `ipv6-addr:value`;
- `file:hashes.MD5`;
- `file:hashes.'SHA-1'`;
- `file:hashes.'SHA-256'`.

### OpenCTI Observable To AdversaryGraph IOC

OpenCTI cyber observable values are normalized where possible.

For example:

```text
IPv4-Addr -> ipv4
Domain-Name -> domain
Url -> url
StixFile hash -> md5 / sha1 / sha256
```

### OpenCTI Labels

OpenCTI labels are preserved as AdversaryGraph IOC tags.

This is useful because labels often contain:

- malware names;
- actor names;
- campaign hints;
- confidence context;
- source family;
- report classification.

### ATT&CK Technique IDs

AdversaryGraph extracts ATT&CK technique IDs from synchronized metadata where available.

For example:

```text
T1059
T1059.001
T1486
T1078
```

Those IDs can later be used for:

- IOC-to-TTP mapping;
- matrix display;
- comparison;
- report generation.

## Operational Use Case

Imagine this situation.

Your OpenCTI instance receives a new report about ransomware infrastructure.

The report contains:

- several domains;
- IP addresses;
- malware family labels;
- a few ATT&CK references;
- analyst notes;
- related indicators.

The workflow becomes:

1. Open AdversaryGraph.
2. Go to Feeds Management.
3. Run Pull from OpenCTI.
4. Open IOC Library.
5. Search/filter the imported indicators.
6. Open IOC enrichment for high-value observables.
7. Map relevant IOCs to ATT&CK TTPs.
8. Compare those TTPs against known actors and campaigns.
9. Add the reviewed techniques to the Navigator matrix.
10. Generate a PDF or Markdown report.
11. Push the reviewed output back to OpenCTI.

The output is not just copied data.

It is improved analyst context.

## Security Notes

The OpenCTI token is read by the backend container from `.env`.

Do not commit `.env`.

Use a token with the minimum required permissions.

Recommended approach:

- create a dedicated OpenCTI user or service account;
- grant only the permissions needed for sync;
- rotate the token periodically;
- keep `OPENCTI_VERIFY_TLS=true` for production;
- use a reverse proxy or VPN if OpenCTI is not public;
- check sync results before using bidirectional sync in production.

AdversaryGraph does not delete OpenCTI objects during sync.

That is deliberate.

For CTI operations, destructive sync should be explicit, reviewed, and audited.

## Limitations

This is a practical integration, not a replacement for a full OpenCTI connector ecosystem.

Important limitations:

- OpenCTI GraphQL schemas can differ between versions.
- The implementation uses fallback queries where possible.
- Some OpenCTI object relationships may require additional mapping logic later.
- Push currently focuses on indicators and reports.
- Advanced OpenCTI relationship creation may need future expansion.
- The integration does not perform attribution.
- Synchronized labels and technique IDs are evidence inputs, not conclusions.

That last point matters.

If an IOC appears near an actor name or report label, it is still an analytical lead. It should be validated before being used as attribution.

## Recommended Workflow

For a careful production workflow:

1. Configure `OPENCTI_URL` and `OPENCTI_TOKEN`.
2. Run Check OpenCTI.
3. Run a small pull with a low limit.
4. Review imported IOCs in IOC Library.
5. Confirm labels, source URLs, and report context.
6. Run enrichment and IOC-to-TTP mapping.
7. Generate a local report.
8. Push a limited set back to OpenCTI.
9. Review the objects inside OpenCTI.
10. Increase sync limits only after validation.

For daily use:

```text
OpenCTI pull -> AdversaryGraph analysis -> enrichment -> report -> OpenCTI push
```

For mature teams:

```text
OpenCTI + MISP + TAXII + OTX + ThreatFox + VirusTotal + local reports
        -> AdversaryGraph operational CTI workflow
        -> detection backlog / matrix / reports / OpenCTI
```

## Final Thoughts

CTI tools should not live in isolation.

OpenCTI is strong as a structured intelligence platform.

AdversaryGraph is focused on the analyst workflow around ATT&CK mapping, IOC enrichment, actor comparison, matrix coverage, and detection handoff.

The new OpenCTI symmetric sync connects those two worlds.

It lets OpenCTI provide the intelligence base.

It lets AdversaryGraph operationalize that intelligence.

And it lets the improved output move back into OpenCTI.

That is the workflow I wanted:

```text
collect -> structure -> analyze -> enrich -> validate -> report -> synchronize
```

## Links

GitHub:

https://github.com/anpa1200/adversarygraph

Documentation:

https://1200km.com/adversarygraph-docs/

Project hub:

https://1200km.com/adversarygraph/

Use cases:

https://1200km.com/adversarygraph/use-cases.html

OpenCTI documentation:

https://docs.opencti.io/latest/

## Follow My Work

I publish practical cybersecurity research, CTI workflows, detection engineering notes, malware analysis projects, OpenCTI work, cloud and Kubernetes security research, AI-assisted security tooling, labs, and technical guides.

Portfolio / Knowledge Base: https://1200km.com/

Medium: https://medium.com/@1200km

GitHub: https://github.com/anpa1200

LinkedIn: https://www.linkedin.com/in/andrey-pautov/

Andrey Pautov
