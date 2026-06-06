# ThreatMapper

**AI-powered MITRE ATT&CK threat intelligence platform.**

Map adversary behaviours to ATT&CK, compare against 160+ APT group profiles, analyse incident reports with Claude / GPT-4o / Gemini, and export Navigator-compatible layers — all in one self-hosted tool.

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [Navigator](#navigator)
  - [AI Analysis](#ai-analysis)
  - [APT Library](#apt-library)
  - [Compare](#compare)
  - [Export](#export)
  - [MITRE Sync](#mitre-sync)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Development](#development)
- [Deployment](#deployment)
- [Tech Stack](#tech-stack)
- [Changelog](#changelog)

---

## Features

| Module | Capability |
|---|---|
| **Navigator** | Full ATT&CK matrix (Enterprise, Mobile, ICS) with D3.js zoom/pan, sub-technique expansion, dual-layer colouring |
| **APT Library** | 160+ named threat groups from MITRE ATT&CK with full TTP profiles, aliases, and overlay-to-Navigator |
| **AI Analysis** | Upload PDF/DOCX/TXT or paste text → streamed LLM extraction of ATT&CK techniques + APT attribution |
| **Compare** | Jaccard similarity ranking of your TTPs vs every APT group; visual matrix diff, tactic breakdown, gap analysis |
| **Export** | ATT&CK Navigator JSON layers, PDF threat intelligence reports, plain JSON |
| **MITRE Sync** | Auto-detects new ATT&CK releases daily (Celery beat), manual sync via API; sidebar shows staleness indicator |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Docker Compose                           │
├────────────────┬───────────────┬──────────────┬─────────────────┤
│  React / Vite  │   FastAPI     │  PostgreSQL  │  Redis + Celery │
│  (port 3000)   │  (port 8000)  │     16       │  worker + beat  │
│                │               │              │                 │
│  nginx proxy   │  SQLAlchemy   │  JSONB for   │  daily MITRE    │
│  serves SPA    │  async ORM    │  STIX data   │  sync job       │
└────────────────┴───────────────┴──────────────┴─────────────────┘
```

**Backend** — Python 3.12, FastAPI, SQLAlchemy 2.x (async), Celery  
**Frontend** — React 18, TypeScript, Vite, D3.js, Tailwind CSS, Zustand  
**Database** — PostgreSQL 16 with JSONB for ATT&CK STIX data  
**Queue** — Redis + Celery (async LLM jobs, daily MITRE sync at 03:00 UTC)

### Data flow

```
User uploads report
        │
        ▼
  _read_input()          ← stream with 50 MB byte-cap, size-check before buffer
        │
        ▼
  LLMAdapter.extract()   ← Claude / GPT-4o / Gemini
        │
        ▼
  _parse_response()      ← JSON extraction with raw_decode fallback
        │
        ▼
  _rank_apt_groups()     ← Jaccard similarity vs every APT group in DB
        │
        ▼
  AnalysisResult → DB    ← session, techniques, APT matches
        │
        ▼
  Frontend renders       ← techniques table, APT ranking, Navigator injection
```

---

## Quick Start

### Prerequisites

- Docker + Docker Compose (v2)
- API key for at least one LLM provider (Claude, OpenAI, or Gemini)

### 1 — Clone and configure

```bash
git clone https://github.com/anpa1200/threatmapper.git
cd threatmapper
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
# Required: at least one AI provider key
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIza...

# Database (defaults are fine for local use)
DB_NAME=threatmapper
DB_USER=tm_user
DB_PASS=changeme_strong_password

# ATT&CK domains to ingest (comma-separated)
ATTCK_DOMAINS=enterprise-attack,mobile-attack,ics-attack

LOG_LEVEL=info
```

> You only need one LLM key. The others can be left blank — the UI will only show providers that have a key configured.

### 2 — Start

```bash
docker compose up
```

**First startup takes 5–15 minutes.** The API container automatically:
1. Runs `create_tables()` to initialise the PostgreSQL schema
2. Downloads the latest ATT&CK STIX bundles from MITRE's GitHub (~105 MB total for all three domains)
3. Parses the STIX 2.1 JSON directly (no third-party ATT&CK library required — Python 3.12 compatible)
4. Upserts tactics, techniques, groups, and all relationships into PostgreSQL

Watch progress:

```bash
docker compose logs -f api
```

Expected output:

```
Parsing enterprise-attack-16.1.json ...
  Parsed: 14 tactics, 641 techniques, 163 groups, 8234 usages
  Ingested 14 tactics
  Ingested 641 techniques
  Ingested 8234 technique-tactic links
  Ingested 163 APT groups
  Ingested 8234 group-technique usages
Finished ingesting enterprise-attack v16.1
```

### 3 — Open

| Service | URL |
|---|---|
| **Frontend** | http://localhost:3000 |
| **API docs** | http://localhost:8000/docs |
| **Health** | http://localhost:8000/api/health |

---

## Usage Guide

### Navigator

The central workspace. The full ATT&CK matrix renders as a colour-coded heatmap.

#### Basic interaction

| Action | How |
|---|---|
| Zoom / pan | Scroll to zoom, drag to pan. Double-click resets view. |
| Select a technique | Click any cell — turns red, added to your TTP layer |
| Expand sub-techniques | Click the ▶ arrow on any parent cell |
| Open detail panel | Click a cell to open the right-side panel (full description, detection notes, data sources, AI assistant) |
| Multi-select | Hold Shift and click multiple cells |
| Search | Type in the search box to filter by name or ATT&CK ID |
| Filter by platform | Use the platform dropdown (Windows, Linux, macOS, Cloud, etc.) |
| Filter by tactic | Use the tactic dropdown to focus on a specific kill-chain phase |

#### Layer toolbar

| Button | Action |
|---|---|
| ↑ Import layer | Load an existing ATT&CK Navigator `.json` layer |
| ↓ Navigator layer | Export your TTPs + overlay as ATT&CK Navigator JSON |
| ↓ JSON | Export selected technique IDs as plain JSON |
| ↓ PDF | Export current layer as a formatted PDF report |
| Expand all | Expand all sub-techniques |
| Collapse all | Collapse all sub-techniques |
| Clear my TTPs | Reset your selection |
| Clear overlay | Remove the APT group overlay |

#### Colour coding

| Colour | Meaning |
|---|---|
| Red `#e94560` | In your TTP layer |
| Blue `#3b82f6` | In the APT overlay only |
| Amber `#f59e0b` | In both layers (shared TTPs) |
| Dark | Not selected |

#### AI Assistant (technique panel)

When you click a technique, the detail panel opens with an embedded chat. Ask anything:

- *"What are the most common detections for this technique?"*
- *"Show me a SIGMA rule skeleton for T1059.001"*
- *"What APT groups use this in combination with lateral movement?"*

Select a provider (Claude / GPT-4o / Gemini) from the dropdown. The context includes the full ATT&CK description for the selected technique.

---

### AI Analysis

Analyse threat intelligence documents — incident reports, malware analysis write-ups, OSINT, CTI feeds — and automatically map every observable behaviour to ATT&CK.

#### Step-by-step

1. Click **Analyze** in the sidebar
2. Select an LLM provider and optionally specify a model
3. Choose a domain (`enterprise-attack`, `mobile-attack`, or `ics-attack`)
4. Either:
   - **Paste text** directly (investigation notes, copy-pasted report sections), or
   - **Upload a file** — PDF, DOCX, or TXT up to 50 MB
5. Click **Analyse with AI**
6. Watch the live SSE token stream as the model thinks
7. When complete, review the three tabs:

| Tab | Content |
|---|---|
| **Techniques** | Extracted ATT&CK technique mappings with confidence score (0–100 %), tactic, and a quoted evidence snippet from your text |
| **APT Matches** | Top 10 APT groups ranked by Jaccard similarity against the extracted techniques |
| **Raw Response** | The full LLM JSON output for debugging |

8. Click **→ Inject into Navigator** to push all extracted techniques into your layer

#### Confidence score guide

| Score | Meaning |
|---|---|
| 90–100 % | Explicitly stated in the text (e.g. "used PowerShell to run encoded commands") |
| 70–89 % | Strongly implied (e.g. "established persistence via registry") |
| 40–69 % | Weakly implied or inferred from context |
| < 40 % | Speculative — treat with caution |

#### Supported file types

| Type | Notes |
|---|---|
| `.pdf` | Text extraction via PyMuPDF; tables and multi-column layouts supported |
| `.docx` | Paragraphs and table cells extracted via python-docx |
| `.txt` / plain text | UTF-8, UTF-8-BOM, latin-1, CP1252 — auto-detected |

Files are truncated at 120,000 characters before being sent to the LLM (~30 k tokens).

#### LLM Chat

The **Chat** button at the bottom of any analysis opens a free-form assistant. Use it to:

- Ask follow-up questions about a specific technique
- Request detection logic (SIGMA rules, KQL queries, Splunk SPL)
- Ask for attacker perspective / defensive controls
- Discuss ATT&CK sub-technique differences

The context field pre-populates with your selected technique IDs. You can also paste arbitrary context (max 8,000 characters).

---

### APT Library

Browse all ATT&CK threat groups.

| Control | Action |
|---|---|
| Search box | Filter by group name or ATT&CK ID (e.g. "APT29", "G0016") |
| Group card | Click to open the full TTP profile |
| Add all to my TTPs | Bulk-load every technique this group uses into your Navigator layer |
| Overlay on Navigator | Show the group's TTPs as a blue overlay on the matrix |
| ATT&CK ↗ | Open the official MITRE group page |

**Full TTP profile** includes:
- All known techniques with ATT&CK IDs, tactic, and use description
- Aliases (other names the group is known by)
- MITRE ATT&CK attribution notes

> **Tip:** Overlay a group, then go to Navigator to see where your selected TTPs overlap with theirs using the amber/blue colour coding.

---

### Compare

Rank every ATT&CK group against your layer by Jaccard similarity index.

**Jaccard similarity** = `|shared techniques| / |union of all techniques|`

A score of 1.0 means the two sets are identical; 0.0 means no overlap. Scores above 0.3 typically indicate a meaningful behavioural match.

#### Workflow

1. Select techniques in Navigator (or run an AI Analysis and inject results)
2. Navigate to **Compare**
3. The ranked list on the left updates in real-time
4. Click any group to open the detail view on the right

#### Detail view tabs

| Tab | Content |
|---|---|
| **Overview** | Similarity score, shared technique chips (clickable), techniques unique to your layer |
| **Tactic Breakdown** | Stacked bar chart — shared / user-only / APT-only counts per kill-chain phase |
| **Visual Diff** | Compact colour-strip matrix showing the overlap across the full ATT&CK matrix |
| **Gap Analysis** | Every technique in the group's known profile that is *not* in your layer |

#### Actions

- **Overlay in Navigator** — send the group to Navigator with your layer as your TTPs and the group as overlay
- **↓ PDF Report** — generate a formatted PDF analysis report combining your TTPs, similarity scores, and gap analysis

---

### Export

#### Analysis PDF

From the **Analyze** page, click **Download PDF** on any completed analysis. The report includes:
- Cover page with metadata (provider, model, domain, session ID)
- Executive summary (AI-generated)
- Extracted techniques table sorted by confidence
- APT attribution section with top 10 matches
- Tactic coverage breakdown

#### Navigator layer PDF

From the **Navigator**, click **↓ PDF** in the toolbar. The report lists all techniques in your current layer with tactics and platforms.

#### ATT&CK Navigator JSON

Click **↓ Navigator layer** to download a `.json` file compatible with [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Import it there for sharing or further annotation.

---

### MITRE Sync

ThreatMapper tracks new ATT&CK releases and keeps the local database up to date.

#### Automatic sync (daily)

A Celery Beat scheduler runs `check_and_sync` every day at 03:00 UTC. It queries MITRE's GitHub repository for new bundle versions and ingests any updates without downtime.

#### Staleness indicator

The sidebar footer shows:
- **Green dot** — all domains are on the latest version
- **Amber pulse** — at least one domain has a newer version available

#### Manual sync

```bash
# Via Make
make ingest

# Via API
curl -X POST http://localhost:8000/api/sync/trigger

# Check status
curl http://localhost:8000/api/sync/status
```

The `/api/sync/status` response shows the current and latest version for each domain:

```json
{
  "domains": [
    {
      "domain": "enterprise-attack",
      "current_version": "16.1",
      "latest_version": "16.1",
      "needs_update": false,
      "last_ingested": "2025-01-15T03:00:00Z"
    }
  ],
  "any_updates_needed": false
}
```

---

## API Reference

Full interactive documentation is available at **http://localhost:8000/docs**.

### ATT&CK Data

```
GET  /api/attack/versions
GET  /api/attack/tactics?domain=enterprise-attack&version=16.1
GET  /api/attack/techniques?domain=enterprise-attack&tactic=initial-access&search=phish&platform=Windows&subtechniques=true
GET  /api/attack/techniques/{attack_id}?domain=enterprise-attack
```

### APT Groups

```
GET  /api/apt/groups?domain=enterprise-attack&search=APT29
GET  /api/apt/groups/{attack_id}
POST /api/apt/compare?domain=enterprise-attack&top_n=10
     body: { "technique_ids": ["T1566", "T1059", "T1078"] }
```

> `technique_ids` is capped at 500 entries.

### Analysis

```
POST /api/analyze
     multipart: provider={claude|openai|gemini}, domain=enterprise-attack, text=... | file=@report.pdf

POST /api/analyze/stream          ← Server-Sent Events
     multipart: same as above

GET  /api/analyze/{session_id}    ← returns AnalysisOut or 202 if still processing

POST /api/analyze/chat
     body: { "message": "...", "provider": "claude", "model": "claude-opus-4-8", "context": "..." }
```

#### SSE event types

| Event `type` | Payload | Meaning |
|---|---|---|
| `token` | `{"content": "..."}` | LLM token streamed in real-time |
| `result` | `{"data": AnalysisOut}` | Final parsed result |
| `error` | `{"message": "..."}` | LLM or DB failure |
| `done` | — | Chat stream completed |

### Export

```
POST /api/export/analysis/{session_id}   → PDF download
POST /api/export/layer
     body: { "technique_ids": ["T1059"], "domain": "enterprise-attack" }
     → PDF download
```

### Sync

```
GET  /api/sync/status
POST /api/sync/trigger
GET  /api/sync/task/{task_id}
```

---

## Configuration

All configuration is via environment variables in `.env`. The table below lists every available setting.

| Variable | Default | Description |
|---|---|---|
| `DB_NAME` | `threatmapper` | PostgreSQL database name |
| `DB_USER` | `tm_user` | Database user |
| `DB_PASS` | `changeme` | Database password — **change this** |
| `ANTHROPIC_API_KEY` | — | Anthropic / Claude API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `ATTCK_DOMAINS` | `enterprise-attack,mobile-attack,ics-attack` | Domains to download and ingest |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warning` / `error` |

You can restrict ingestion to a single domain to speed up first start:

```env
ATTCK_DOMAINS=enterprise-attack
```

---

## Development

### Project structure

```
threatmapper/
├── backend/
│   ├── app/
│   │   ├── api/routes/          # FastAPI routers
│   │   │   ├── analyze.py       # POST /analyze, /analyze/stream, /analyze/chat
│   │   │   ├── attack.py        # GET /attack/tactics, /techniques
│   │   │   ├── apt.py           # GET /apt/groups, POST /apt/compare
│   │   │   ├── export.py        # POST /export/analysis, /export/layer
│   │   │   └── sync.py          # GET /sync/status, POST /sync/trigger
│   │   ├── core/
│   │   │   ├── config.py        # Pydantic Settings from .env
│   │   │   └── database.py      # async engine, session factory, create_tables
│   │   ├── models/
│   │   │   ├── analysis.py      # AnalysisSession, AnalysisResult, UserLayer
│   │   │   └── attack.py        # AttackVersion, Tactic, Technique, AptGroup, …
│   │   ├── services/
│   │   │   ├── ai/
│   │   │   │   ├── base.py      # LLMAdapter ABC, SYSTEM_PROMPT, _parse_response
│   │   │   │   ├── claude.py    # Anthropic adapter
│   │   │   │   ├── openai.py    # OpenAI adapter
│   │   │   │   ├── gemini.py    # Google Gemini adapter
│   │   │   │   └── factory.py   # get_adapter(provider, model)
│   │   │   ├── attck/
│   │   │   │   ├── downloader.py     # Fetch STIX bundles from MITRE GitHub
│   │   │   │   ├── ingestor.py       # Parse STIX 2.1 JSON, upsert to PostgreSQL
│   │   │   │   └── version_checker.py
│   │   │   ├── file_parser.py   # PDF / DOCX / TXT text extraction
│   │   │   └── report_generator.py  # fpdf2 PDF builder
│   │   └── tasks/
│   │       ├── celery_app.py    # Celery + Redis config
│   │       ├── analysis.py      # Background analysis tasks
│   │       └── sync.py          # check_and_sync Celery task
│   ├── tests/
│   │   ├── unit/                # No DB required
│   │   └── integration/         # FastAPI TestClient + mocked DB
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── Navigator/       # AttackMatrix, LayerControls, TechniquePanel,
│       │   │                    # LLMChat, MatrixFilters, LayerImport
│       │   └── Compare/         # MatrixDiff, TacticBreakdown
│       ├── hooks/               # useAttackMatrix, useSseStream
│       ├── pages/               # Navigator, APTLibrary, Analyze, Compare
│       ├── store/               # Zustand global state
│       ├── api/client.ts        # Axios + TanStack Query setup
│       └── types/attack.ts      # TypeScript interfaces
├── nginx/nginx.conf             # Reverse proxy + Vite dev proxy config
├── docker-compose.yml
├── Makefile
└── .env.example
```

### Makefile shortcuts

```bash
make up           # docker compose up --build
make build        # rebuild all images
make down         # stop and remove containers
make logs         # follow api + worker logs
make shell-api    # bash into the api container
make shell-db     # psql into postgres
make ingest       # trigger ATT&CK re-ingestion manually
make reset        # tear down volumes and rebuild from scratch (destructive)
```

### Running tests

```bash
# Inside the api container (real PostgreSQL):
docker compose exec api pytest tests/ -v

# Locally (unit + mocked DB, no PostgreSQL needed):
cd backend
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -v --no-cov
```

**Test suite:**

| Suite | Tests | Coverage |
|---|---|---|
| `unit/test_file_parser.py` | 9 | PDF/DOCX/TXT extraction, truncation, encoding edge cases |
| `unit/test_ai_base.py` | 11 | JSON parsing, code-fence stripping, noise extraction, prompt structure |
| `unit/test_comparison.py` | 10 | Jaccard similarity, ranking, empty-set edge cases |
| `integration/test_attack_routes.py` | 10 | Health, versions, tactics, techniques — API shape and error paths |
| `integration/test_apt_routes.py` | 9 | Group listing, compare endpoint, export, analysis input validation |

### Adding a new LLM provider

1. Create `backend/app/services/ai/myprovider.py` extending `LLMAdapter`:

```python
class MyProviderAdapter(LLMAdapter):
    def __init__(self, model: str = "my-model") -> None:
        self._model = model
        self._api_client = MySDK(api_key=settings.my_provider_api_key)

    @property
    def provider(self) -> str:
        return "myprovider"

    @property
    def model(self) -> str:
        return self._model

    async def _raw_complete(self, system: str, user: str) -> str:
        ...

    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        ...
```

2. Register in `factory.py`'s `get_adapter`
3. Add to `ALLOWED_PROVIDERS` in `analyze.py`
4. Add the provider to the frontend dropdowns in `Analyze.tsx` and `LLMChat.tsx`

### Database schema notes

ThreatMapper uses SQLAlchemy's `create_all()` on startup — no migration framework is required for a fresh install. If you are upgrading an existing deployment, apply these `ALTER TABLE` statements manually:

```sql
-- Added in v0.2.1: stores the ATT&CK domain for each analysis session
ALTER TABLE analysis_sessions
  ADD COLUMN IF NOT EXISTS domain VARCHAR(50) NOT NULL DEFAULT 'enterprise-attack';
```

---

## Deployment

### Security checklist

- [ ] Set a strong `DB_PASS` in `.env`
- [ ] Never commit `.env` to git (it is in `.gitignore`)
- [ ] For any internet-facing deployment, place ThreatMapper behind a reverse proxy (nginx, Caddy) with TLS and authentication (HTTP Basic Auth, OAuth 2.0 proxy, or VPN)
- [ ] ThreatMapper has no built-in user authentication — all endpoints are open on the local network
- [ ] API keys are read from environment variables at startup and never stored in the database

### Scaling

- The API runs a single uvicorn worker by default. For concurrent users, add `--workers 4` in `docker-compose.yml`.
- Celery workers scale horizontally — add additional `worker` service instances in `docker-compose.yml`.
- The PostgreSQL connection pool is set to 10 connections (max 20 overflow) — adequate for most single-server deployments.

### Updating ATT&CK data

```bash
# Quickest:
curl -X POST http://localhost:8000/api/sync/trigger

# Via Makefile:
make ingest

# Check what version is currently ingested:
curl http://localhost:8000/api/sync/status | python -m json.tool
```

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Backend framework | FastAPI 0.115 | Async, OpenAPI auto-docs |
| ORM | SQLAlchemy 2.x (async) | asyncpg driver |
| Database | PostgreSQL 16 | JSONB for STIX arrays |
| Task queue | Celery 5.4 + Redis 7 | Daily ATT&CK sync, async LLM jobs |
| ATT&CK parsing | stdlib `json` only | No mitreattack-python; Python 3.12-compatible |
| AI — Claude | `anthropic` SDK | Cached async client |
| AI — OpenAI | `openai` SDK | JSON mode on non-streaming; cached client |
| AI — Gemini | `google-generativeai` | JSON MIME type; `configure()` called once |
| File parsing | PyMuPDF (PDF), python-docx (DOCX) | Streamed with 50 MB hard cap |
| PDF reports | fpdf2 | Multi-page with tactic coverage charts |
| Frontend framework | React 18 + TypeScript | |
| Build tool | Vite 6 | |
| Visualisation | D3.js 7 | ATT&CK matrix heatmap |
| Styling | Tailwind CSS 3 | |
| State | Zustand 5 | |
| Data fetching | TanStack Query 5 | |
| Testing | pytest, pytest-asyncio, httpx | |

---

## Changelog

### v0.2.1 (2026-06-06)

**Security fixes:**
- File uploads are now streamed with a 64 KB chunk reader; the 50 MB guard fires before the entire body is buffered in RAM, eliminating a memory-DoS window
- `/apt/compare` now enforces a maximum of 500 technique IDs to prevent CPU-exhaustion attacks
- `ChatRequest.context` is capped at 8,000 characters; `model` is validated against an allowlist pattern before being forwarded to LLM provider SDKs

**Correctness fixes:**
- Analysis sessions that fail during the post-stream DB write are now marked `status=failed` — they no longer appear as orphaned `processing` sessions that return 404 on retrieval
- `AnalysisSession` gains a `domain` column; PDF exports now show the domain used for the actual analysis instead of always showing `enterprise-attack`
- `GET /analyze/{id}` and `POST /export/analysis/{id}` now return `JSONResponse(status_code=202)` instead of raising `HTTPException(202)` — clients that check `response.ok` no longer mishandle the in-progress state
- Layer PDF technique count now matches the table rows (derived from DB results, not the raw client-supplied ID list)

**Performance / reliability:**
- Anthropic, OpenAI, and Gemini SDK clients are cached in each adapter's `__init__`; connection pools are now reused across requests instead of being created on every LLM call
- `_parse_response` fallback now uses `json.JSONDecoder().raw_decode()` instead of a greedy `re.DOTALL` regex; trailing prose containing bare braces no longer corrupts the JSON extraction

### v0.2.0 (2026-06-06)

- Initial release: Navigator, AI Analysis, APT Library, Compare, Export, MITRE Sync
- STIX bundle parsing rewritten to use stdlib `json` only (Python 3.12 compatibility, drops `mitreattack-python` dependency)
- Fixed tactic matrix ordering: uses canonical ATT&CK kill-chain sort instead of alphabetical

---

## License

MIT — see [LICENSE](LICENSE).

ATT&CK® is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.
