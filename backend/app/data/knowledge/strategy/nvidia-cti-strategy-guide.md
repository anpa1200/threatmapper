# NVIDIA Product CTI Strategy — Full Practitioner Guide

> **Scope:** Cyber Threat Intelligence programme covering NVIDIA networking, AI-infrastructure,
> and adjacent products. Covers strategic design, collection discipline, OSINT, WEBINT,
> darknet monitoring, open-source tooling, and commercial platform integration.
> Grounded in the public vulnerability and threat-actor picture established in prior
> research (June 2026 baseline).

---

## Table of Contents

1. [Intelligence Cycle and Strategic Foundation](#1-intelligence-cycle-and-strategic-foundation)
2. [Asset Taxonomy and Threat Surface Map](#2-asset-taxonomy-and-threat-surface-map)
3. [Priority Intelligence Requirements (PIRs)](#3-priority-intelligence-requirements-pirs)
4. [OSINT — Open Source Intelligence](#4-osint--open-source-intelligence)
5. [WEBINT — Web Intelligence](#5-webint--web-intelligence)
6. [Technical Vulnerability Intelligence](#6-technical-vulnerability-intelligence)
7. [Darknet and Underground Monitoring](#7-darknet-and-underground-monitoring)
8. [Threat Actor Tracking](#8-threat-actor-tracking)
9. [Open-Source Tools and Platforms](#9-open-source-tools-and-platforms)
10. [Commercial Tools and Platforms](#10-commercial-tools-and-platforms)
11. [Collection Management and Workflow](#11-collection-management-and-workflow)
12. [Analysis Methodology](#12-analysis-methodology)
13. [Dissemination and Reporting Framework](#13-dissemination-and-reporting-framework)
14. [Detection and Hunting Integration](#14-detection-and-hunting-integration)
15. [Metrics and Programme Maturity](#15-metrics-and-programme-maturity)
16. [Reference Tables](#16-reference-tables)

---

## 1. Intelligence Cycle and Strategic Foundation

### 1.1 The Intelligence Cycle Applied to NVIDIA CTI

The standard intelligence cycle — Direction, Collection, Processing, Analysis, Dissemination,
Feedback — must be adapted for the specifics of NVIDIA product security:

```
┌─────────────────────────────────────────────────────────────┐
│                     DIRECTION                               │
│   PIRs → Collection Plan → Source Tasking                   │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                     COLLECTION                              │
│   OSINT · WEBINT · TECHINT · Darknet · Vendor feeds         │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                     PROCESSING                              │
│   Normalise → Deduplicate → Tag → Store (TIP/SIEM)          │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                     ANALYSIS                                │
│   Confidence scoring → ATT&CK mapping → PIR answering       │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                     DISSEMINATION                           │
│   SOC · VulnMgmt · Architecture · CISO · PSIRT              │
└──────────────────────┬──────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                     FEEDBACK                                │
│   PIR re-tasking · Gap analysis · Programme maturity        │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Intelligence Levels

Run all three levels in parallel. They answer different questions.

| Level | Question | Cycle time | Primary consumers |
|---|---|---|---|
| **Strategic** | What is the long-term threat trajectory for NVIDIA AI infrastructure? | Monthly / quarterly | CISO, board, product security leadership |
| **Operational** | Is a specific actor or campaign currently targeting NVIDIA networking products? | Weekly | SOC leads, incident response, threat hunters |
| **Tactical** | What specific IoCs, CVEs, or TTPs should we act on now? | Daily / real-time | SOC analysts, vulnerability management, detection engineers |

### 1.3 Confidence Model

Use a three-tier model for all findings. Apply it consistently and always surface it in reports.

| Confidence | Definition | Example |
|---|---|---|
| **High** | Primary source confirmation: NVIDIA PSIRT bulletin, NVD record, or verified incident report | CVE-2025-23256 in BlueField management interface |
| **Medium** | Credible secondary source or strong analytic inference from adjacent evidence | Volt Typhoon TTPs assessed likely applicable to Spectrum switches |
| **Low** | Academic PoC, single unverified report, or hypothetical attack path | ReDMArk RDMA packet injection in enterprise AI cluster |

Mark confidence explicitly in every product you produce. Never omit it.

---

## 2. Asset Taxonomy and Threat Surface Map

Build this inventory before writing PIRs. Without it, PIRs are disconnected from reality.

### 2.1 Product Tiers

| Tier | Products | Why it is the highest priority |
|---|---|---|
| **Tier 1 — Control plane** | BlueField DPU (all generations), DOCA framework, BlueField BMC, SNAP-4 | Compromise operates below host OS visibility; persistence survives reinstall |
| **Tier 2 — Fabric / switching** | Cumulus Linux, NVOS, Spectrum Ethernet switches, Quantum InfiniBand, ONYX | Carries all east-west GPU training traffic; compromise enables full traffic interception |
| **Tier 3 — Compute boundary** | ConnectX adapters, NVIDIA Container Toolkit, GPU Operator, vGPU | Container escape or firmware pivot into host; connects compute to fabric |
| **Tier 4 — Management and services** | NVUE interface, AIStore, Riva, Triton, Omniverse, GPU display drivers | Exposed APIs, credential leakage, misconfig-driven resource abuse |
| **Tier 5 — Edge / embedded** | Jetson, DRIVE, Isaac | Physical access exposure, insecure defaults, remote automotive attack surface |

### 2.2 Exposed Surfaces by Product

```
BlueField DPU
├── BMC (out-of-band management)
├── DOCA microservices (Argus, Vault, collectx telemetry)
├── PCIe boundary to host
└── Firmware update chain

Cumulus Linux / NVOS
├── NVUE REST/CLI interface
├── SSH management plane
├── BGP/OSPF routing daemons
├── SNMP
└── Log handling (password-hash leakage surface)

NVIDIA Container Toolkit
├── OCI hooks (enable-cuda-compat)
├── libnvidia-container
└── LD_PRELOAD environment variable parsing

ConnectX / SuperNIC
├── Firmware (manual update chain)
├── VPI host driver
└── RDMA/RoCE data path (no native encryption)
```

### 2.3 Deployment Context Questions

Answer these before finalising your threat model. Risk differs sharply depending on deployment.

- Are management interfaces (NVUE, BMC, DOCA) internet-reachable or strictly segmented?
- Is the environment single-tenant, research-shared, or commercial multi-tenant?
- Is RoCEv2 / InfiniBand traffic encrypted (IPsec/MACsec) or plaintext?
- Are firmware updates automated (patch governance) or manual?
- Is Cumulus/NVOS exposed to corporate LAN or isolated to a dedicated OOB network?
- What NVIDIA product versions are deployed? Map against current PSIRT bulletin version matrices.

---

## 3. Priority Intelligence Requirements (PIRs)

PIRs are the formal questions your CTI programme must answer. They drive collection tasking.
Review and update quarterly.

### PIR-1 — Active Exploit Development (CRITICAL)
**Question:** Are threat actors actively developing, discussing, trading, or testing exploits
targeting NVIDIA DPU management planes, NVUE interfaces, or DOCA components?

**Collection sources:** Dark web exploit forums, Telegram IAB channels, GitHub PoC monitoring,
NVD KEV additions, Shodan/Censys for exposed NVUE/BMC endpoints.

**Key indicators:** CVE-specific chatter (CVE-2025-33179, CVE-2025-33181, CVE-2025-23256,
CVE-2025-23266); keywords "NVUE", "BlueField firmware", "Mellanox ipfilter", "DOCA collectx";
PoC repositories on GitHub targeting NVIDIA networking.

**Decision supported:** Emergency out-of-cycle patching, customer communications, internal
red team tasking.

**Cadence:** Continuous / real-time alert.

---

### PIR-2 — State Actor Expansion to NVIDIA Switch Infrastructure (HIGH)
**Question:** Are Volt Typhoon, Flax Typhoon, or Salt Typhoon expanding their documented
edge-device targeting methodology to include NVIDIA Spectrum switches or Cumulus Linux
environments?

**Collection sources:** CISA/FBI/NCSC joint advisories, Mandiant/CrowdStrike public reporting,
incident response telemetry sharing (ISACs), customer IR reports.

**Key indicators:** KV Botnet staging observed on Spectrum/Mellanox hardware; unexplained
modifications to switch ipfilter ACL rules; rogue SSH sessions on Cumulus Linux from unusual
IP ranges; anomalous BGP route changes; SNMP enumeration from non-admin subnets.

**Decision supported:** Hardening factory default configurations; zero-trust switch deployment
guidelines; network segmentation reviews.

**Cadence:** Weekly review of threat landscape reporting; real-time CISA advisory monitoring.

---

### PIR-3 — In-the-Wild Exploitation of Container Toolkit (CRITICAL)
**Question:** Is CVE-2025-23266 (NVIDIAScape) being actively exploited in cloud AI cluster
environments to escape container isolation?

**Collection sources:** Cloud provider telemetry (AWS/Azure/GCP security blogs), Kubernetes
security community, honeypot data, managed security service provider reporting.

**Key indicators:** Anomalous LD_PRELOAD environment variable injection targeting
nvidia-container-toolkit or enable-cuda-compat OCI hooks; unexpected process executions
originating from container hook phases; exploitation chatter in underground forums.

**Decision supported:** Forced deprecation of enable-cuda-compat hook; emergency advisory
to managed AI cloud customers.

**Cadence:** Continuous / real-time alert.

---

### PIR-4 — State Actor Targeting of NVIDIA IP and GPU Architecture (HIGH)
**Question:** Are APT41, APT40, or similar semiconductor-focused state actors demonstrating
targeted interest in NVIDIA GPU microarchitecture, DPU designs, AI model weights, or
CUDA/DOCA source code?

**Collection sources:** Counter-intelligence community reporting, spear-phishing campaign
tracking (PhishTank, URLscan), supply chain monitoring, insider threat telemetry,
dark web dump analysis.

**Key indicators:** Spear-phishing targeting NVIDIA hardware engineers or Mellanox R&D staff;
anomalous large-volume outbound transfers from engineering network segments; appearance
of NVIDIA-attributed proprietary code or schematics on underground markets.

**Decision supported:** Zero-trust access controls for R&D environments; enhanced endpoint
monitoring for engineering staff; IP protection protocol revisions.

**Cadence:** Monthly strategic review; immediate alert on confirmed credential theft from
engineering personnel.

---

### PIR-5 — Supply Chain Compromise in NVIDIA Software Dependencies (HIGH)
**Question:** Have open-source components used in DOCA Debian packages, CUDA toolkits,
or NVIDIA AI frameworks (NeMo, Triton, PyTorch) been affected by supply chain compromise?

**Collection sources:** OpenSSF, NVD, OSV, Snyk, Socket.dev, GitHub Dependabot alerts,
NVIDIA SBOM publications, SLSA provenance attestations.

**Key indicators:** Malicious commits in upstream repositories directly imported by NVIDIA
stacks; typosquat packages mimicking NVIDIA libraries; compromised CI/CD pipeline artefacts
in NVIDIA AI Cluster Runtime or NVSentinel.

**Decision supported:** Internal code audits; CI/CD pipeline halts; SBOM updates.

**Cadence:** Daily automated scanning; immediate on confirmed malicious commit.

---

### PIR-6 — GPU/Interconnect Side-Channel Weaponisation (MEDIUM)
**Question:** Is academic GPU side-channel research (Mercury, NVBleed, GPUHammer, ReDMArk)
transitioning from PoC into operational threat tools usable against multi-tenant AI clusters?

**Collection sources:** arXiv cs.CR, USENIX Security / IEEE S&P / CCS proceedings, exploit
framework repositories (Metasploit, GitHub), underground forum technical discussions.

**Key indicators:** Public release of weaponised tooling based on Mercury/NVBleed/GPUHammer
techniques; forum discussions referencing GPU memory extraction in cloud contexts; CVEs
filed against RDMA stack components citing these research lineages.

**Decision supported:** Restricting performance counter access in shared GPU environments;
enabling IPsec/MACsec on RoCEv2 fabrics; tenant isolation architecture changes.

**Cadence:** Monthly research sweep; quarterly strategic update.

---

### PIR-7 — Iranian Actor Targeting of Israeli NVIDIA R&D Facilities (MEDIUM)
**Question:** Are UNC3890 or related Iranian APT clusters increasing targeting intensity
against NVIDIA's Yokneam / Kiryat Tivon R&D facilities or Israeli networking division staff?

**Collection sources:** Mandiant/Google Threat Intelligence Iran-nexus reporting, Israeli
CERT (CERT-IL) advisories, open-source geopolitical reporting, OSINT on watering hole
campaigns targeting Israeli tech sector.

**Key indicators:** UNC3890 TTPs (SUGARUSH/SUGARDUMP implants) observed in Israeli tech
sector; watering hole campaigns on sites frequented by NVIDIA Israel staff; credential
harvesting targeting @nvidia.com addresses from Israeli IP ranges.

**Decision supported:** Enhanced physical and cyber security protocols for Israeli facilities;
personnel awareness training; network segmentation between Israel R&D and global production.

**Cadence:** Monthly review; immediate on confirmed Israeli tech sector campaign.

---

## 4. OSINT — Open Source Intelligence

### 4.1 NVIDIA Primary Sources

These are the highest-confidence sources. Monitor them before anything else.

**NVIDIA PSIRT and Security Bulletins**
- NVIDIA Product Security page: `nvidia.com/en-us/product-security/`
- NVIDIA PSIRT GitHub repository: `github.com/NVIDIA` — security advisories published
  since October 2025; older bulletins being backfilled
- Subscribe to GitHub security advisories for repositories:
  `NVIDIA/open-gpu-kernel-modules`, `NVIDIA/container-toolkit`, `NVIDIA/DOCA-*`,
  `NVIDIA/aistore`, `NVIDIA/NVSentinel`, `NVIDIA/aicr`
- NVIDIA Developer Blog for security-relevant product announcements:
  `developer.nvidia.com/blog`
- NVIDIA Security Disclosure Policy: documents expected response timelines and
  responsible disclosure process

**NVIDIA Documentation Changes**
- Monitor NVIDIA Docs (`docs.nvidia.com`) for security-relevant documentation updates
  to DOCA, Cumulus Linux, NVOS, BlueField, ConnectX firmware guides
- RSS feeds available on developer.nvidia.com for some product families
- NVIDIA Release Notes for Cumulus Linux, NVOS, DOCA — security fixes are listed
  in changelog sections

### 4.2 Government and Authoritative Sources

**US Government**
- CISA Known Exploited Vulnerabilities (KEV) catalogue: `cisa.gov/known-exploited-vulnerabilities-catalog`
  — subscribe to RSS; KEV addition for any NVIDIA CVE is an immediate action trigger
- CISA Advisories: `cisa.gov/cybersecurity-advisories` — primary source for Volt Typhoon,
  Salt Typhoon, Flax Typhoon joint advisories
- FBI Cyber Division public notices: `ic3.gov` and `fbi.gov/investigate/cyber`
- NSA Cybersecurity Advisories: `nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/`
- NIST NVD: `nvd.nist.gov` — subscribe to vendor=nvidia CVE feed
  (API endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:*:nvidia:*`)

**International**
- NCSC (UK): `ncsc.gov.uk/section/keep-up-to-date/ncsc-news` — often co-publishes with CISA
- BSI (Germany): `bsi.bund.de/EN/` — publishes ICS/network device advisories
- ANSSI (France): `cert.ssi.gouv.fr`
- CERT-IL (Israel): `cert.gov.il` — directly relevant for PIR-7 (Israeli facility targeting)
- ENISA: `enisa.europa.eu/publications`
- ASD/ACSC (Australia): `cyber.gov.au/about-us/advisories`

**MITRE**
- ATT&CK Enterprise: `attack.mitre.org` — technique updates relevant to network device targeting
- ATT&CK ICS: applicable where NVIDIA products appear in industrial control or OT contexts
- CVE Programme: `cve.org` — authoritative CVE records
- CWE: `cwe.mitre.org` — weakness taxonomy; useful for pattern analysis across bulletins

### 4.3 Vulnerability and Exploit Databases

| Source | URL | What it provides | Cadence |
|---|---|---|---|
| NVD | nvd.nist.gov | Authoritative CVE records, CVSS scores, CPE mappings | Real-time |
| CVE.org | cve.org | CVE records, CNA assignments | Real-time |
| CISA KEV | cisa.gov/kev | Confirmed in-the-wild exploitation | Real-time |
| Exploit-DB | exploit-db.com | Public exploit code, PoCs | Daily |
| Packet Storm | packetstormsecurity.com | Exploits, advisories, tools | Daily |
| VulnDB (Risk Based Security) | vulndb.cyberriskanalytics.com | Proprietary vuln intelligence | Commercial |
| Snyk | snyk.io | Open-source library CVEs (DOCA deps, AI libs) | Real-time |
| OSV | osv.dev | Open-source vulnerability database | Real-time |
| GitHub Advisory Database | github.com/advisories | GHSA records including NVIDIA repos | Real-time |
| OpenCVE | opencve.io | CVE tracking with vendor filters | Real-time |

**NVIDIA-specific NVD query:**
```
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=NVIDIA&keywordExactMatch=false&resultsPerPage=50
```

**CVE alert keywords to monitor for NVIDIA:**
`bluefield`, `connectx`, `mellanox`, `cumulus linux`, `nvos`, `nvue`, `doca`,
`nvidia container toolkit`, `spectrum switch`, `quantum infiniband`, `jetson`,
`omniverse`, `aistore`

### 4.4 Social Media and Community OSINT

**Twitter/X**
Key accounts to monitor for NVIDIA product security disclosures:
- `@NVIDIASecurity` (official PSIRT)
- `@NVIDIASW` (software announcements)
- Security researchers who have previously disclosed NVIDIA CVEs:
  monitor authors of CVE-2025-23266 (NVIDIAScape), CVE-2025-33179/33181
- `@CVEnew` — automated CVE publication feed
- `@cisa_cyber` — CISA alerts
- Hashtags: `#NVIDIA`, `#BlueField`, `#CumulusLinux`, `#NVUE`, `#DOCA`, `#NVIDIAScape`

Use **TweetDeck** or **Tweetmonk** to maintain persistent monitoring columns.
Archive tweets via **TWINT** (open-source) before they are deleted.

**LinkedIn**
- NVIDIA security engineers and PSIRT team members publishing vulnerability disclosures
- Mellanox/NVIDIA networking division announcements
- Security researcher profiles disclosing NVIDIA research

**Reddit**
- `r/netsec` — security research announcements
- `r/nvidia` — user-reported driver/firmware vulnerabilities
- `r/sysadmin`, `r/networking` — Cumulus/NVOS operational issues that may indicate CVEs

**Mastodon/Infosec.exchange**
Growing security researcher community; many researchers now announce findings here
before or instead of Twitter.

**GitHub**
- Search: `nvidia CVE site:github.com`
- Monitor for new repositories with names containing: `nvidia-exploit`, `nvue-bypass`,
  `bluefield-pwn`, `doca-privesc`, `container-escape-nvidia`
- Set up `github.com/search?q=nvidia+vulnerability&type=repositories` as a saved search
- Use **GitMon** or **GitHub Actions** to watch for new forks of NVIDIA security-relevant
  repositories

### 4.5 Academic and Research OSINT

These sources are the 6–18 month forward-looking signal. By the time a paper appears at
a top venue, adversaries have read it too.

| Conference / Source | URL | Relevance |
|---|---|---|
| USENIX Security | usenix.org/conferences/byname/108 | GPU side-channel, RDMA attacks, container security |
| IEEE S&P (Oakland) | ieeesplore.ieee.org | Hardware security, firmware analysis |
| ACM CCS | sigsac.org/ccs | Cloud security, AI security, network attacks |
| NDSS | ndss-symposium.org | Network and distributed systems security |
| Black Hat | blackhat.com/us-26/briefings.html | Pre-release security research, often NVIDIA-adjacent |
| DEF CON | defcon.org/html/defcon-34/dc-34-cfp.html | Hardware hacking, firmware analysis |
| arXiv cs.CR | arxiv.org/list/cs.CR/recent | Preprints; earliest signal for GPU/interconnect attacks |
| Google Scholar alerts | scholar.google.com | Set alert for: "NVIDIA" AND ("vulnerability" OR "side-channel" OR "RDMA" OR "BlueField") |
| Semantic Scholar | semanticscholar.org | Academic paper discovery with citation tracking |

**Critical papers to track as baseline (already published):**
- Mercury — remote side-channel against NVIDIA deep learning accelerator
- NVBleed — NVLink timing leakage across VMs
- GPUHammer — GDDR6 Rowhammer on NVIDIA GPUs
- ReDMArk — RDMA QPN spoofing and BTH forgery
- NeVerMore — NVMe-oF RDMA exploit framework

### 4.6 Security Conference Talks and Blogs

**Blogs to monitor (RSS)**
- Project Zero: `googleprojectzero.blogspot.com`
- Synacktiv: `synacktiv.com/en/publications`
- Quarkslab: `blog.quarkslab.com`
- Eclypsium: `eclypsium.com/blog` — firmware and supply chain
- Red Balloon Security: `redballoonsecurity.com/research` — embedded/firmware
- Binarly: `binarly.io/posts` — firmware and UEFI
- Tenable Research: `tenable.com/blog/research`
- Rapid7 AttackerKB: `attackerkb.com` — exploitability assessments

**Conference talk monitoring**
- Black Hat USA/EU/Asia speaker previews (submitted abstracts often leaked)
- DEF CON talk database: `defcon.org/html/defcon-34/dc-34-speakers.html`
- CanSecWest, RootCon, Hack.lu, Troopers for European research
- Hardware security: `escar-europe.org`, `hardwear.io`

---

## 5. WEBINT — Web Intelligence

WEBINT extends OSINT to active web-based collection, including exposed asset discovery,
paste site monitoring, and structured web search techniques.

### 5.1 Exposed Asset Discovery (Shodan / Censys)

This is one of the most actionable WEBINT techniques: find your own exposed NVIDIA management
surfaces before attackers do, and monitor for newly exposed instances globally.

**Shodan queries for NVIDIA networking surfaces:**

```
# NVUE REST API (Cumulus Linux / NVOS default port 8765)
port:8765 product:"NVUE"

# BlueField BMC / Redfish interface
product:"Redfish" org:"NVIDIA"

# Mellanox switch management
"Mellanox" port:443 http.title:"Login"

# DOCA management services
product:"DOCA"

# General NVIDIA management interfaces
org:"NVIDIA Corporation" port:22 OR port:443 OR port:8443

# Exposed NVIDIA Riva endpoints (speech AI - known misconfiguration target)
http.title:"NVIDIA Riva" port:50051 OR port:8000

# Cumulus Linux SSH banners
"Cumulus Networks" port:22
```

**Censys queries:**
```
services.software.product="Cumulus Linux"
services.software.vendor="Mellanox"
autonomous_system.name="NVIDIA"
services.http.response.html_title="NVUE"
```

**Usage workflow:**
1. Run queries weekly; diff results against prior week
2. Any new exposure in your ASN is an immediate incident trigger
3. Global exposure monitoring (external to your ASN) informs PIR-1 (are attackers finding
   targets?) and supports threat landscape reporting

**Tools:**
- Shodan: `shodan.io` — commercial ($49/month for Small Business)
- Censys: `censys.io` — commercial (free tier available)
- FOFA: `fofa.info` — Chinese internet scanner; often finds exposures Shodan misses
- ZoomEye: `zoomeye.org` — alternative scanner, useful for cross-validation
- BinaryEdge: `binaryedge.io` — network scanning with historical data
- GreyNoise: `greynoise.io` — mass-scan and exploitation activity classification

### 5.2 Certificate Transparency Monitoring

New TLS certificates issued for NVIDIA-related domains or subdomains can indicate:
- New management interfaces being brought online
- Phishing infrastructure mimicking NVIDIA developer portals
- Adversary-controlled infrastructure impersonating NVIDIA services

**Tools:**
- crt.sh: `crt.sh/?q=%.nvidia.com` — free, near real-time
- Cert Spotter: `sslmate.com/certspotter`
- Facebook CT: `developers.facebook.com/tools/ct`
- Cloudflare Certificate Search: `cloudflare.com/ssl/ct-log`

**Monitor for:**
- Certificates issued for `*.nvidia.com`, `*.mellanox.com`, `*.cumulus.ai`
- Typosquats: `nvdia.com`, `nvidla.com`, `mellanox-security.com`, `nvidia-psirt.com`
- New subdomains on nvidia.com that may indicate internal infrastructure exposure

### 5.3 Paste Site Monitoring

Paste sites are a primary channel for data leak notification, credential dumps,
and early PoC publication.

| Site | URL | What to watch for |
|---|---|---|
| Pastebin | pastebin.com | NVIDIA credential dumps, config pastes, PoC snippets |
| GitHub Gist | gist.github.com | PoC code, vulnerability notes |
| Ghostbin | ghostbin.co | Less moderated; malware configs |
| Rentry | rentry.co | Technical notes, exploit documentation |
| PrivateBin instances | various | Self-hosted paste instances on TOR/clearnet |
| Hastebin | hastebin.com | Developer paste; sometimes PoC code |
| Pastes.io | pastes.io | Alternative to Pastebin |

**Automated paste monitoring tools:**
- **PasteHunter** (open-source): `github.com/kevthehermit/PasteHunter`
  — scrapes paste sites for regex patterns; configure patterns for NVIDIA keywords
- **Dumpmon** (open-source): `github.com/jordan-wright/dumpmon`
- **Pastemon**: commercial paste monitoring in many CTI platforms

**Paste monitoring regex patterns for NVIDIA:**
```regex
(?i)(nvidia|bluefield|connectx|cumulus\s?linux|nvos|nvue|doca|mellanox)
(?i)(CVE-202[0-9]-[0-9]{4,5}).*(?i)(nvidia|bluefield|mellanox)
(?i)(nvidia|mellanox).*(password|credential|hash|token|secret|api.?key)
(?i)(bluefield|connectx|spectrum).*(exploit|bypass|privesc|rce|lpe)
```

### 5.4 Domain and Typosquat Monitoring

Adversaries register typosquat domains to:
- Host phishing pages targeting NVIDIA engineers or customers
- Distribute malicious firmware update "tools"
- Impersonate NVIDIA support for social engineering

**Tools:**
- **dnstwist**: `github.com/elceef/dnstwist` — generates typosquat variations
  and checks registration status
- **URLscan.io**: `urlscan.io` — monitors newly scanned URLs; search for
  `nvidia` or `mellanox` in page content
- **PhishTank**: `phishtank.org` — crowdsourced phishing URL database
- **OpenPhish**: `openphish.com` — automated phishing detection feed
- **VirusTotal Graph**: `virustotal.com` — visualise domain/IP relationships

**Monitor variations of:**
`nvidia.com`, `mellanox.com`, `ngc.nvidia.com` (container registry),
`developer.nvidia.com`, `psirt.nvidia.com`

### 5.5 Job Posting Intelligence

Threat actor TTPs and targeting can be inferred from job postings. Also useful
for understanding NVIDIA's own security priorities.

**What to watch:**
- NVIDIA job postings for "BlueField security", "DOCA security", "PSIRT engineer"
  indicate where product security investment is going
- Security vendor postings seeking "NVIDIA firmware reverse engineer" may indicate
  active research
- Dark web job postings seeking "NVIDIA network expertise" or "BlueField kernel developer"
  are a direct threat signal

**Sources:** LinkedIn, Indeed, Glassdoor, Handshake, levels.fyi

### 5.6 WHOIS and Infrastructure Pivoting

When a threat actor or suspicious domain is identified, pivot on infrastructure:

**Tools:**
- **WhoisXML API**: `whoisxmlapi.com` — bulk WHOIS and reverse WHOIS
- **Domaintools**: `domaintools.com` — pivoting, historical WHOIS
- **Spyse** (now Censys): historical infrastructure data
- **Hurricane Electric BGP Toolkit**: `bgp.he.net` — ASN and IP pivoting
- **Robtex**: `robtex.com` — DNS and IP relationships
- **VirusTotal**: passive DNS, file/IP/domain relationships

---

## 6. Technical Vulnerability Intelligence

### 6.1 Patch and Bulletin Tracking Workflow

Establish a formal workflow so no NVIDIA bulletin is missed:

```
TRIGGER SOURCES (parallel monitoring)
├── NVIDIA PSIRT GitHub → GitHub Security Advisory webhook
├── NVD API → filtered on vendor=nvidia
├── CISA KEV → RSS feed
└── CVE.org → CNA=NVIDIA filtered feed
         ↓
TRIAGE (within 4 hours of publication)
├── Identify affected product tier (1–5)
├── Assign CVSS / exploitability assessment
├── Cross-reference against deployed asset inventory
└── Determine exposure (internet-facing? admin-only? isolated?)
         ↓
PRIORITY CLASSIFICATION
├── CRITICAL: CVSS ≥9.0 OR KEV listed OR PoC public
├── HIGH: CVSS 7.0–8.9, management interface or control plane
├── MEDIUM: CVSS 4.0–6.9, limited exposure
└── LOW: CVSS <4.0, no exposure path confirmed
         ↓
DISSEMINATION
├── CRITICAL → Immediate alert to SOC + VulnMgmt + CISO
├── HIGH → Same-day advisory to VulnMgmt
├── MEDIUM/LOW → Next scheduled patch cycle bulletin
```

### 6.2 NVIDIA-Specific CVE Tracking Queries

**NVD API (JSON):**
```bash
# All NVIDIA CVEs modified in last 30 days
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?\
  cpeName=cpe:2.3:*:nvidia:*&\
  lastModStartDate=2026-05-25T00:00:00.000&\
  lastModEndDate=2026-06-25T23:59:59.999" \
  | jq '.vulnerabilities[].cve | {id: .id, description: .descriptions[0].value}'
```

**CISA KEV monitoring (check for NVIDIA entries):**
```bash
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq '.vulnerabilities[] | select(.vendorProject=="NVIDIA")'
```

### 6.3 Exploitability Assessment Sources

Beyond CVSS, use these to assess real-world exploitability:

| Source | URL | What it provides |
|---|---|---|
| AttackerKB | attackerkb.com | Community exploitability assessments |
| EPSS | first.org/epss | Probability-based exploitation prediction score |
| VulnCheck | vulncheck.com | KEV extended; exploitation status |
| Nuclei Templates | github.com/projectdiscovery/nuclei-templates | Check if CVE has a Nuclei detection template (= PoC exists) |
| Metasploit modules | github.com/rapid7/metasploit-framework | Check if CVE has MSF module |
| ExploitDB | exploit-db.com | Public exploits |
| sploitus | sploitus.com | Exploit aggregator; cross-references ExploitDB, GitHub, Packetstorm |

### 6.4 Firmware Intelligence

NVIDIA firmware (ConnectX, BlueField, Spectrum) is an under-monitored surface.

**Resources:**
- NVIDIA Firmware Downloads: `network.nvidia.com/support/firmware/` — version tracking
- Binwalk (open-source): firmware analysis and extraction
- Ghidra + NVIDIA firmware: reverse engineer firmware images for undisclosed changes
- Eclypsium Platform: commercial firmware integrity monitoring
- BINARLY: commercial platform for firmware vulnerability analysis
- LVFS (Linux Vendor Firmware Service): `fwupd.org/lvfs/devicelist` — check if NVIDIA
  participates for automated firmware update tracking

**Firmware monitoring practice:**
- Download each new firmware release for Tier 1/2 products
- Diff against prior release using binwalk/bindiff
- Any unexplained new binary blob or changed interrupt handler warrants investigation

### 6.5 Software Bill of Materials (SBOM)

NVIDIA publishes SBOM and SLSA Build Provenance attestations for critical components
(NVSentinel, AI Cluster Runtime). Use these to:
- Track third-party library dependencies for upstream CVEs
- Identify supply chain risk before NVIDIA issues a bulletin
- Automate vulnerability matching against deployed NVIDIA software

**SBOM tools:**
- **Syft** (open-source): generate SBOM from container images
- **Grype** (open-source): vulnerability scan against SBOM
- **Dependency-Track** (open-source OWASP): SBOM management and vulnerability tracking
- **Anchore Enterprise**: commercial SBOM and container security

**Workflow:** Pull NVIDIA container images from NGC (`nvcr.io`), generate SBOM with Syft,
scan with Grype, ingest results into Dependency-Track.

---

## 7. Darknet and Underground Monitoring

### 7.1 Overview and Legal/Operational Context

Darknet monitoring for CTI purposes is a **passive collection discipline** — you observe
and report; you do not engage, purchase, or conduct active operations. Maintain strict
operational security throughout:

- Use dedicated, isolated infrastructure (separate VM, no personal accounts)
- Route through Tor Browser (never your corporate network)
- Do not download files or executables from darknet sources
- Do not create accounts unless your organisation has a formal cover persona programme
- Document all access for legal compliance; consult your legal team before beginning
- Many CTI platforms (Recorded Future, Flashpoint, Intel 471) access darknet sources
  on your behalf, removing the need for direct access

### 7.2 Darknet Forum Categories Relevant to NVIDIA CTI

**Exploit markets and exploit forums**
These sell zero-days, PoCs, and access. Monitor for NVIDIA product mentions.

| Forum / Market | Type | Relevance |
|---|---|---|
| XSS.is | Russian exploit forum | Network device exploits, firmware analysis |
| Exploit.in | Russian market/forum | Initial access broker listings, exploit sales |
| RaidForums successors (BreachForums) | English | Data dumps, credential leaks |
| RAMP | Russian-language ransomware | Ransomware affiliate programme chatter |
| Nulled.to | Crimeware | Lower-tier exploit sharing |
| Cracked.io | Crimeware | Credential stuffing tools |
| KernelMode.info (legacy) | Rootkit/kernel | Kernel exploit research (closed but archived) |

**What to look for:**
- Threads titled with NVIDIA CVE IDs (CVE-2025-33179, CVE-2025-23266, etc.)
- Keywords: "BlueField", "Mellanox", "NVUE", "Cumulus", "DOCA", "ConnectX"
- "0day for network switch OS", "DPU firmware implant"
- NVIDIA-signed driver abuse: "NVIDIA cert signed" + RAT/implant keywords

**Initial Access Broker (IAB) markets**
IABs sell authenticated access to corporate networks. Any listing for "AI company",
"semiconductor company", "data centre operator", or "HPC environment" warrants
investigation for NVIDIA relevance.

| Market | Notes |
|---|---|
| Genesis Market (disrupted) | Archived listings remain relevant for TTP analysis |
| Russian Market | Active; sells stealer logs including corporate VPN credentials |
| 2easy Market | Stealer log market; monitor for nvidia.com domain credentials |

**Ransomware group leak sites (clearnet TOR mirrors)**
Published by ransomware groups when victims refuse to pay. Monitor for:
- NVIDIA customer organisations using NVIDIA AI infrastructure
- NVIDIA partners (Mellanox resellers, integrators)
- Any HPC or AI lab data leaks that may expose NVIDIA configurations

Active groups with leak sites (as of mid-2026): LockBit successors, RansomHub,
Akira, BlackSuit, Qilin, Hunters International.

### 7.3 Telegram Monitoring

Telegram is the primary communication channel for cybercriminal groups and many
IAB operations. It is accessible without Tor Browser.

**Channel categories to monitor:**

| Category | Examples | What to monitor |
|---|---|---|
| IAB announcement channels | Various private/invite-only | NVIDIA customer access listings |
| Ransomware PR channels | Group announcement channels | Victim listings in AI/semiconductor |
| Exploit announcement | CTF-adjacent, underground research | NVIDIA CVE PoC announcements |
| Data leak channels | Exposed databases, credential dumps | nvidia.com email/password pairs |
| Malware distribution | Stealer C2, RAT distribution | Malware signed with NVIDIA certs |
| DDoS-for-hire | Booter services | Relevant if NVIDIA infrastructure is targeted |

**Tools for Telegram monitoring:**
- **TGStat**: `tgstat.com` — Telegram channel analytics and search
- **Telegago**: Telegram search engine
- **OSINT Industries**: `osint.industries` — Telegram username/phone pivoting
- **Telepathy** (open-source): `github.com/jordanwildon/Telepathy` — Telegram group archiver
- **TelegramScraper**: open-source channel content scraper
- Commercial platforms (Recorded Future, Flashpoint) monitor Telegram at scale

**Search queries for Telegram:**
```
nvidia exploit OR nvidia vulnerability OR bluefield OR cumulus linux OR DOCA
nvidia CVE OR NVUE bypass OR "mellanox" OR "ConnectX"
```

### 7.4 Dark Web Data Leak Monitoring

**Credential leak monitoring (for NVIDIA-related domains):**
Target domains: `nvidia.com`, `mellanox.com`, `ngc.nvidia.com`, `developer.nvidia.com`

| Source | URL | Notes |
|---|---|---|
| HaveIBeenPwned API | haveibeenpwned.com/API/v3 | Domain-level breach monitoring |
| DeHashed | dehashed.com | Leaked credential database search |
| LeakCheck | leakcheck.io | Real-time breach monitoring |
| BreachDirectory | breachdirectory.org | Aggregated breach data |
| Snusbase | snusbase.com | Commercial credential search |
| IntelX (Intelligence X) | intelx.io | Dark web, paste, breach data search |

**For your own organisation's NVIDIA deployment:**
Monitor for credentials associated with:
- Service accounts used to access NVUE/BMC management interfaces
- NVIDIA NGC API keys (leaked NGC tokens allow pulling proprietary containers)
- DOCA service account credentials

### 7.5 Dark Web Search Engines and Infrastructure

| Tool | URL | Notes |
|---|---|---|
| Ahmia | ahmia.fi | Tor hidden service search engine (clearnet) |
| Torch | accessible via Tor | Oldest Tor search engine |
| DarkSearch | darksearch.io | Dark web search with API |
| Intelligence X | intelx.io | Indexes dark web, paste sites, data leaks |
| Onion Search Engine | multiple | Various Tor-accessible search engines |

### 7.6 Commercial Darknet Monitoring Services

For most organisations, direct darknet access is neither necessary nor advisable.
These commercial services provide monitored, curated darknet intelligence:

| Platform | Vendor | Strengths |
|---|---|---|
| Recorded Future | Recorded Future | Industry-leading darknet coverage; NVIDIA-specific entity tracking |
| Flashpoint | Flashpoint | Deep criminal forum coverage; IAB market monitoring |
| Intel 471 | Intel 471 | Criminal actor profiling; malware intelligence |
| Digital Shadows (ReliaQuest) | ReliaQuest | Attack surface + darknet; brand monitoring |
| ZeroFox | ZeroFox | Dark web + social media monitoring |
| Cybersixgill | Cybersixgill | Real-time darknet collection; API-first |
| Mandiant Advantage | Google | Integrated actor intelligence + darknet |
| ThreatConnect | ThreatConnect | TIP with built-in darknet feeds |

---

## 8. Threat Actor Tracking

### 8.1 Actor Profiles Relevant to NVIDIA Products

**LAPSUS$ / DEV-0537 (HIGH CONFIDENCE — Direct)**
- Motivation: Financial extortion, data theft, notoriety
- Confirmed NVIDIA action: 2022 breach, 1TB exfiltration, code-signing certificate theft
- Current relevance: Stolen certs still weaponised by criminal ecosystem; 2022 breach
  may have disclosed internal architecture useful for future targeting
- Tracking sources: Krebs on Security, Group-IB reporting, court filings (UK prosecution)
- Monitor for: Resurgence of LAPSUS$ methodology; new groups mimicking their playbook;
  NVIDIA-signed certificate abuse (check driver signature verification on endpoints)

**Volt Typhoon (PRC) (HIGH CONFIDENCE — Indirect)**
- Motivation: Pre-positioning in US critical infrastructure for potential kinetic conflict
- Documented TTPs: LOTL, KV Botnet, router/switch compromise, credential extraction,
  long-dwell passive collection
- NVIDIA relevance: Spectrum switches and Cumulus Linux are functionally identical targets
  to documented Volt Typhoon victims (Cisco, Fortinet, Netgear)
- Tracking sources: CISA/NSA/FBI joint advisories, Microsoft MSTIC, Secureworks CTU,
  Lumen Black Lotus Labs
- Monitor for: CISA advisories naming new device classes; KV Botnet expansion reporting;
  any confirmed Volt Typhoon activity on Linux-based network OS

**Salt Typhoon (PRC) (HIGH CONFIDENCE — Indirect)**
- Motivation: Telecommunications intelligence collection; strategic communications intercept
- Documented TTPs: Management plane compromise of telecom infrastructure; router targeting
- NVIDIA relevance: Same management-plane tradecraft applies to NVUE and BlueField BMC;
  AI cluster communications fabric is a strategic target
- Tracking sources: Reuters, Washington Post, CISA advisories, SentinelOne, CrowdStrike
- Monitor for: New reporting on Salt Typhoon victim profiles expanding beyond telecom

**Flax Typhoon (PRC) (MEDIUM CONFIDENCE — Indirect)**
- Motivation: Botnet infrastructure for espionage and attack concealment
- Documented TTPs: Mass-compromising edge routers and IoT devices for proxy networks
- NVIDIA relevance: If enterprise networking devices (Spectrum, Cumulus) are within their
  targeting envelope, they provide high-value infrastructure access
- Tracking sources: Microsoft MSTIC, NSA/CISA advisory on Flax Typhoon botnet
- Monitor for: Expansion of device type targeting beyond legacy consumer routers

**APT41 / Winnti Group (PRC) (HIGH CONFIDENCE — Sector level)**
- Motivation: IP theft for semiconductor and AI capability gap closure; financial crime
- Documented TTPs: Supply chain compromise, custom rootkits/bootkits, prolonged stealthy
  persistence, insider threat utilisation
- NVIDIA relevance: NVIDIA GPU architecture, DOCA source code, AI training methodologies
  are exactly the IP this group is known to target
- Tracking sources: Mandiant APT41 report, HHS advisory, DOJ indictments
- Monitor for: Spear-phishing campaigns targeting semiconductor engineers; supply chain
  compromise of NVIDIA dependency repositories

**UNC3890 / APT34-adjacent (Iran) (HIGH CONFIDENCE — Geographic)**
- Motivation: Espionage against Israeli targets; disruption
- Documented TTPs: Watering holes, credential harvesting, SUGARUSH/SUGARDUMP implants,
  supply chain targeting of Israeli tech sector
- NVIDIA relevance: Yokneam R&D centre and planned Kiryat Tivon campus are high-value targets;
  Mellanox acquisition made NVIDIA a major Israeli technology employer
- Tracking sources: Mandiant/Google Cloud Threat Intelligence, ClearSky, Check Point Research
- Monitor for: Campaigns targeting Israeli tech sector employees; watering holes on
  Israeli tech news sites

**Criminal Ransomware Operators (HIGH CONFIDENCE — General)**
- Motivation: Financial extortion
- NVIDIA relevance: Any major AI infrastructure operator or NVIDIA customer is a ransomware
  target; BlueField-protected environments may be specifically targeted to disable
  security controls before deployment
- Tracking sources: CISA ransomware advisories, Mandiant M-Trends, Verizon DBIR,
  ransomware group leak sites
- Monitor for: Ransomware TTPs specifically referencing DPU or network infrastructure
  bypass; victims in AI/HPC sector

### 8.2 Actor Tracking Infrastructure

**Open-source threat actor databases:**
- **MITRE ATT&CK Groups**: `attack.mitre.org/groups/` — canonical TTP reference
- **Malpedia**: `malpedia.caad.fkie.fraunhofer.de` — actor and malware family database
- **APT Groups and Operations** (Google Sheets): maintained by ThaiCERT
- **ETDA Thailand APT Groups**: `apt.etda.or.th/apt-groups.html`
- **Threat Actor Encyclopedia** (ISAC feeds): various sector ISAC publications

**Commercial actor intelligence:**
- Mandiant Advantage (Google): deepest APT profiling, especially Chinese and Russian actors
- CrowdStrike Adversary Intelligence: named actor profiles with TTPs
- SentinelOne SentinelLabs: public reporting + commercial platform
- Recorded Future Insikt Group: actor tracking with darknet correlation
- Intel 471 INTEL471: criminal actor profiling, malware-as-a-service tracking

---

## 9. Open-Source Tools and Platforms

### 9.1 Threat Intelligence Platforms (TIPs)

**MISP (Malware Information Sharing Platform)**
- URL: `misp-project.org`
- Description: Industry-standard open-source TIP; stores IoCs, TTPs, threat reports
- NVIDIA CTI use: Central repository for all NVIDIA-related IoCs, CVE annotations,
  actor profiles; share with ISAC communities
- Key features: STIX/TAXII, MITRE ATT&CK integration, feed ingestion,
  correlation engine, REST API
- Deployment: Docker or VM; requires 8GB+ RAM for production
- Feeds to add: CIRCL OSINT, abuse.ch, MalwareBazaar, Feodo Tracker, URLhaus,
  PhishTank, CISA KEV feed

**OpenCTI**
- URL: `opencti.io` / `github.com/OpenCTI-Platform/opencti`
- Description: Graph-based TIP focused on relationship mapping; STIX2 native
- NVIDIA CTI use: Visualise relationships between actors, CVEs, TTPs, NVIDIA products;
  superior graph interface to MISP for analyst work
- Key features: STIX2, ATT&CK integration, connector ecosystem (100+ connectors),
  knowledge graph, report management
- Deployment: Docker Compose; requires 16GB+ RAM
- Recommended connectors: MISP, CISA KEV, NVD, AlienVault OTX, Shodan,
  MITRE ATT&CK, Mandiant (with licence)

**Cortex + TheHive**
- URL: `thehive-project.org`
- Description: Incident response case management (TheHive) + automated analysis (Cortex)
- NVIDIA CTI use: Case management for NVIDIA vulnerability incidents and threat actor
  sightings; automated IoC enrichment via Cortex analysers
- Cortex analysers: VirusTotal, Shodan, MISP, MaxMind, DomainTools, Censys, Robtex

### 9.2 Monitoring and Alerting Tools

**Vulnerability Monitoring**
- **Vulnrichment** (CISA): `github.com/cisagov/vulnrichment` — enriched CVE data
- **vFeed**: CVE correlation and mapping database
- **cvemon**: simple CVE monitoring CLI
- **MISP ZMQ** + NVD feed: real-time CVE ingestion into MISP

**Network Exposure Monitoring**
- **Shodan Monitor**: alert on new exposure events for your IP ranges (commercial add-on)
- **Censys Exposure Management**: continuous monitoring of your attack surface
- **Nuclei** (ProjectDiscovery): `github.com/projectdiscovery/nuclei`
  — template-based vulnerability scanner; run against your own NVIDIA management interfaces
  to detect known CVEs; check if CVE-2025-33179, CVE-2025-23266 templates exist
- **Naabu**: port scanner; fast subnet scanning to discover management interface exposure
- **httpx**: HTTP probe for enumerating management web UIs

**Paste Site and Web Monitoring**
- **PasteHunter**: `github.com/kevthehermit/PasteHunter` — Pastebin monitoring
- **PULSEDIVE** (free tier): threat intelligence with paste monitoring
- **ChangeDetection.io**: monitor any web page for changes (NVIDIA PSIRT page, NVD entries)
- **Watcher** (open-source): OSINT monitoring framework for web and paste sites

**Social Media and Feed Monitoring**
- **RSS aggregators**: FreshRSS, Miniflux, Tiny Tiny RSS — aggregate all vendor/CERT RSS feeds
- **OSINT Framework**: `osintframework.com` — reference map of OSINT sources
- **Twint** (archived): historical Twitter OSINT; use **nitter** instances for current
- **Maltego** (commercial with free CE): OSINT graph pivoting; NVIDIA entity transforms

### 9.3 Analysis Tools

**STIX and ATT&CK**
- **MITRE ATT&CK Navigator**: `github.com/mitre-attack/attack-navigator`
  — visualise ATT&CK coverage; build NVIDIA threat actor heat maps
- **PyAttack**: Python library for ATT&CK integration
- **Cacao** (OASIS): playbook format for ATT&CK-aligned response procedures

**Malware and IoC Analysis**
- **VirusTotal**: `virustotal.com` — file, URL, IP, domain analysis
- **MalwareBazaar**: `bazaar.abuse.ch` — malware sample repository
- **Any.run**: interactive malware sandbox
- **Cuckoo Sandbox**: self-hosted malware analysis
- **CAPE Sandbox**: `github.com/kevoreilly/CAPEv2` — advanced Cuckoo fork
- **JoeSandbox** (commercial): deep behavioural analysis

**Firmware Analysis**
- **Binwalk**: `github.com/ReFirmLabs/binwalk` — firmware extraction and analysis
- **Ghidra**: `ghidra-sre.org` — NSA reverse engineering tool; NVIDIA firmware analysis
- **Binary Ninja** (commercial): advanced binary analysis
- **IDA Pro** (commercial): industry-standard disassembler

**Network and Packet Analysis**
- **Wireshark**: baseline RDMA/RoCE traffic for anomaly detection
- **Zeek**: `zeek.org` — network traffic analysis framework
- **Suricata**: IDS/IPS; write rules for NVUE injection patterns

### 9.4 Automation and Orchestration

- **TheHive + Cortex + MISP**: integrated SOAR-lite stack for CTI
- **WALKOFF** (NSA): `github.com/nsacyber/WALKOFF` — security orchestration
- **Shuffle** (open-source SOAR): `shuffler.io` — workflow automation
- **n8n**: general workflow automation; useful for connecting CTI sources
- **Apache Airflow**: pipeline orchestration for large-scale collection workflows

---

## 10. Commercial Tools and Platforms

### 10.1 Threat Intelligence Platforms (Commercial)

| Platform | Vendor | Best for | Pricing tier |
|---|---|---|---|
| Recorded Future Intelligence Cloud | Recorded Future | Breadth of collection; darknet; actor tracking; NVIDIA entity monitoring | Enterprise |
| ThreatConnect | ThreatConnect | TIP + SOAR integration; threat library | Mid-market to Enterprise |
| Anomali ThreatStream | Anomali | Feed management; SIEM integration | Mid-market |
| Mandiant Advantage | Google Cloud | APT intelligence; deepest China-nexus actor profiling | Enterprise |
| IBM X-Force Exchange | IBM | Threat feeds; integration with QRadar | Mid-market |
| ThreatQ | ThreatQuotient | Relationship-centric TIP; analyst workflow | Mid-market |
| Palo Alto AutoFocus | Palo Alto Networks | Malware intelligence; Unit 42 research integration | Enterprise |

**Recommendation for NVIDIA CTI:** Recorded Future + OpenCTI. Recorded Future provides
collection depth (especially darknet and actor tracking); OpenCTI provides the relationship
graph and analyst workflow layer at no licence cost.

### 10.2 Vulnerability Intelligence Platforms (Commercial)

| Platform | Vendor | Strengths |
|---|---|---|
| VulnDB | Risk Based Security | Broadest CVE coverage; NVD data lag mitigation |
| Nucleus Security | Nucleus Security | Vulnerability management + CTI correlation |
| Vulcan Cyber | Vulcan Cyber | Risk-based vuln prioritisation; SBOM integration |
| Tenable.io + Lumin | Tenable | Asset-based vuln management; Cyber Exposure scoring |
| Qualys VMDR | Qualys | Continuous vulnerability management; patch orchestration |
| Rapid7 InsightVM | Rapid7 | Vulnerability management; AttackerKB integration |
| Kenna Security (Cisco) | Cisco | Predictive risk scoring; EPSS integration |

**For NVIDIA specifically:** Tenable.io or Qualys VMDR integrated with NVIDIA asset inventory
for continuous scan of management interfaces; VulnDB for pre-NVD CVE notification.

### 10.3 Attack Surface Management (Commercial ASM)

| Platform | Vendor | Notes |
|---|---|---|
| Censys Attack Surface Management | Censys | Certificate, service, and exposure discovery |
| Recorded Future Attack Surface Intelligence | Recorded Future | External exposure + darknet correlation |
| CyCognito | CyCognito | Subsidiary and third-party exposure |
| Mandiant Attack Surface Management | Google | Broad internet-facing asset discovery |
| Expanse (Cortex Xpanse) | Palo Alto Networks | Asset discovery + exposure risk scoring |
| RiskIQ (now Microsoft Defender EASM) | Microsoft | Domain and IP attribution |

**NVIDIA use case:** Run ASM against all IP ranges associated with NVIDIA product deployments
to discover exposed NVUE REST APIs, BMC interfaces, DOCA management endpoints.

### 10.4 Dark Web Monitoring (Commercial)

| Platform | Vendor | Coverage focus |
|---|---|---|
| Recorded Future Dark Web | Recorded Future | Russian, Chinese, English forums; Telegram; markets |
| Flashpoint | Flashpoint | Criminal forums (XSS, Exploit.in, BreachForums); chat |
| Intel 471 | Intel 471 | Criminal actor profiling; malware intelligence |
| Digital Shadows (ReliaQuest) | ReliaQuest | Brand protection + dark web |
| Cybersixgill | Cybersixgill | Real-time darknet; API-first; Telegram |
| ZeroFox | ZeroFox | Dark web + social media + physical threats |
| Tidal Cyber | Tidal Cyber | Adversary intelligence library |

### 10.5 Endpoint and SIEM Integration

Your CTI programme outputs must feed into detection. Key integrations:

**SIEM platforms:**
- Splunk (with Splunk SOAR + Recorded Future integration)
- Microsoft Sentinel (with Threat Intelligence blade; MISP connector available)
- IBM QRadar (X-Force Exchange integration)
- Elastic SIEM (free tier available; ECS-based; good for structured CTI data)
- Google Chronicle (with MITRE ATT&CK integration)

**EDR/XDR platforms relevant to NVIDIA environments:**
- CrowdStrike Falcon (most deployments; strong Linux kernel coverage)
- SentinelOne (strong Linux EDR; good for Cumulus/NVOS monitoring where agent is deployable)
- Microsoft Defender for Endpoint
- Palo Alto Cortex XDR

**Specialised for NVIDIA environments:**
- DOCA Argus: NVIDIA's own DPU-resident runtime threat detection (zero-copy memory analysis)
  — deploy this on all BlueField DPUs; it is the most effective detection at Tier 1
- Falco (open-source): eBPF-based container security; primary tool for NVIDIAScape detection

---

## 11. Collection Management and Workflow

### 11.1 Collection Plan Template

For each PIR, maintain a collection plan record:

```
PIR ID:         PIR-1
PIR text:       Active exploit development for NVIDIA DPU/Switch OS
Owner:          [Analyst name]
Review date:    2026-09-25

Sources assigned:
  - NVD API (automated, daily) → MISP
  - NVIDIA PSIRT GitHub (webhook, real-time) → MISP
  - Recorded Future (actor/CVE entity monitoring) → MISP + Analyst review
  - Shodan (weekly query for NVUE exposure) → CSV → MISP
  - Paste monitoring (PasteHunter, regex set NVIDIA-1) → daily digest

Current status:  No confirmed exploit activity for target CVEs
Last updated:    2026-06-25
Confidence:      High for absence (no positive intelligence)
Next review:     2026-07-25
```

### 11.2 Feed Ingestion Architecture

```
AUTOMATED FEEDS (ingest into MISP or OpenCTI)
├── NVD API → nvd2misp connector
├── CISA KEV → misp-modules
├── NVIDIA PSIRT GitHub → custom webhook → MISP
├── AlienVault OTX → OTX MISP connector
├── abuse.ch (URLhaus, Feodo, MalwareBazaar) → MISP feeds
├── Shodan → shodan2misp
├── CIRCL OSINT → MISP internal feed
└── Emerging Threats rules → Suricata/Snort integration

MANUAL/ANALYST FEEDS (enrich in OpenCTI)
├── Recorded Future reports → analyst ingest
├── Mandiant APT reports → structured ingest
├── CISA/NSA/FBI joint advisories → report + IoC extraction
├── Academic papers → annotated PDFs + ATT&CK mapping
└── Dark web monitoring (commercial platform output) → analyst review
```

### 11.3 Source Reliability Matrix

Assign a reliability rating to each source using the Admiralty Scale:

| Rating | Meaning | Examples |
|---|---|---|
| A — Completely reliable | No doubt about authenticity, trustworthiness | NVIDIA PSIRT bulletins, NVD, CISA KEV |
| B — Usually reliable | Minor doubts; most information valid | NCSC/NSA advisories, Mandiant, CrowdStrike |
| C — Fairly reliable | Some doubts; proved valid in the past | SentinelOne, Tenable blog, reputable news outlets |
| D — Not usually reliable | Significant doubts; occasional valid | Single-source forum posts, unverified researcher claims |
| E — Unreliable | Mostly invalid; cannot be relied on | Anonymous darknet posts without corroboration |
| F — Cannot be judged | No basis for evaluation | New source, first report |

Combine with Information Credibility (1-6):
- 1 = Confirmed by other sources
- 2 = Probably true
- 3 = Possibly true
- 4 = Doubtful
- 5 = Improbable
- 6 = Cannot be judged

**Standard rating format in reports:** `B2` (Usually reliable, probably true).

---

## 12. Analysis Methodology

### 12.1 Structured Analytic Techniques (SATs)

Use these to avoid common analytical failures:

**Analysis of Competing Hypotheses (ACH)**
For every major assessment (e.g., "Is Volt Typhoon actively targeting Spectrum switches?"),
list competing hypotheses and test each against the evidence. ACH prevents confirmation bias.

**Key Assumptions Check**
Periodically list and challenge your working assumptions. Example:
- Assumption: "NVIDIA networking CVEs are not being actively exploited"
- Challenge: Is this absence of evidence or evidence of absence? What would confirm it?

**Devil's Advocate**
Assign an analyst to argue against the prevailing assessment before finalising.
Critical for high-confidence assessments where group-think is a risk.

**Indicators and Warnings (I&W)**
Define in advance what observable events would indicate a threat actor has shifted
from capability development to active operations against NVIDIA infrastructure:
- KEV listing of any Tier 1/2 NVIDIA CVE
- PoC exploit published for BlueField or NVUE
- Confirmed IR engagement at an AI/HPC organisation citing NVIDIA-specific TTPs
- Underground forum credible claim of NVIDIA network access for sale

### 12.2 ATT&CK-Based Analysis

For every NVIDIA vulnerability or threat actor TTP, map to ATT&CK. Maintain a running
navigator layer for your NVIDIA threat model.

**Core NVIDIA ATT&CK technique set:**

| Tactic | Technique | NVIDIA relevance |
|---|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application | NVUE, BlueField BMC, DOCA APIs |
| Initial Access | T1195 — Supply Chain Compromise | DOCA packages, NGC container images |
| Execution | T1059.004 — Unix Shell | NVUE command injection |
| Execution | T1106 — Native API | DOCA API abuse |
| Privilege Escalation | T1068 — Exploitation for Priv Esc | CVE-2025-23257/23258 DOCA collectx |
| Privilege Escalation | T1611 — Escape to Host | CVE-2025-23266 NVIDIAScape |
| Privilege Escalation | T1574.006 — LD_PRELOAD | NVIDIAScape exploitation mechanism |
| Defense Evasion | T1553.002 — Code Signing | LAPSUS$ cert abuse |
| Defense Evasion | T1014 — Rootkit | Theoretical DPU firmware implant |
| Defense Evasion | T1622 — Debugger Evasion | GPU side-channel evasion |
| Credential Access | T1552 — Unsecured Credentials | Cumulus/NVOS password hash in logs |
| Credential Access | T1003 — OS Credential Dumping | Network device credential extraction |
| Lateral Movement | T1021 — Remote Services | Pivot via BMC/SSH from compromised switch |
| Lateral Movement | T1210 — Exploit Remote Services | RDMA fabric lateral movement |
| Collection | T1005 — Data from Local System | GPU model weight exfiltration |
| Exfiltration | T1567 — Exfiltration Over Web Service | AI IP exfiltration to cloud |
| Impact | T1499 — Endpoint Denial of Service | SNAP-4 guest DoS, ipfilter exhaustion |

### 12.3 Evidence Weighting

Apply consistently across all analysis products:

```
HIGH STRENGTH
└── NVIDIA PSIRT bulletin (vendor-confirmed)
└── NVD CVE record with CVSS score
└── CISA KEV listing (confirmed exploitation)
└── Verified incident report by major IR firm
└── DOJ/CISA/NSA joint advisory naming specific actor

MEDIUM STRENGTH
└── Quality vendor CTI report on adjacent sector targeting
└── Academic paper at peer-reviewed venue with methodology
└── ISAC sharing (vetted member community)
└── Multiple corroborating secondary sources

LOW STRENGTH
└── Single-source forum post (unverified)
└── Academic preprint (not yet peer-reviewed)
└── Inference from analogous targeting patterns
└── Anonymous tip or single darknet claim
```

---

## 13. Dissemination and Reporting Framework

### 13.1 Report Types and Templates

**Flash Report (Tactical — within 2 hours of critical finding)**

Triggered by: KEV addition, PoC publication, credible darknet exploit claim, major
NVIDIA bulletin for Tier 1/2 products.

Format:
```
FLASH REPORT — NVIDIA CTI
Date/Time: [UTC timestamp]
TLP: RED (restrict to named recipients) / AMBER / GREEN

SUBJECT: [One-line summary]

WHAT HAPPENED: [2–3 sentences max]
AFFECTED PRODUCTS: [Specific product + version]
SEVERITY: CRITICAL / HIGH / MEDIUM
CVE (if applicable): [CVE ID + CVSS score]
EXPLOITATION STATUS: [Confirmed / PoC available / No known exploitation]
IMMEDIATE ACTION REQUIRED: [Specific patch version or mitigation]
PIR STATUS: [Which PIR this answers or partially answers]
CONFIDENCE: [High/Medium/Low + rating e.g. A2]
NEXT UPDATE: [Estimated time of next report]
```

**Weekly Threat Digest (Operational)**

For: SOC leads, vulnerability management, incident response leads.

Sections:
1. New NVIDIA CVEs this week (with exploitability assessment)
2. Actor activity relevant to NVIDIA infrastructure (new reporting or advisories)
3. PIR status updates
4. Exposure monitoring summary (Shodan/Censys changes)
5. Darknet monitoring summary (any NVIDIA-relevant chatter)
6. Upcoming research / conference talks to watch

**Monthly Strategic Brief (Strategic)**

For: CISO, product security leadership, architecture teams.

Sections:
1. Threat landscape assessment (confidence-rated)
2. Actor capability trend analysis
3. Product risk scoring update (Tier 1–5 heat map)
4. PIR review — answered, active, new requirements
5. Programme gap analysis
6. Recommended strategic decisions

**Vulnerability Advisory (Operational — per PSIRT bulletin)**

For: Vulnerability management, system owners, patch teams.

Sections:
1. CVE summary with CVSS, exploitability, EPSS score
2. Affected product families and version ranges
3. Attack scenario description (narrative: what an attacker could do)
4. Detection indicators (where applicable)
5. Patch versions and deployment priority
6. Compensating controls if patch not immediately deployable

### 13.2 TLP (Traffic Light Protocol) Usage

Always apply TLP to every report:

| TLP | Use for | Distribution |
|---|---|---|
| TLP:RED | Darknet intelligence, active exploitation, sensitive actor attribution | Named individuals only |
| TLP:AMBER+STRICT | Internal threat assessments, PIR answers | Organisation only |
| TLP:AMBER | ISAC-shareable intelligence | Community members only |
| TLP:GREEN | Public-source summaries, general advisories | Community; no public posting |
| TLP:CLEAR | Public CVE summaries, published research | Unrestricted |

### 13.3 ISAC / Information Sharing

Participate in relevant sharing communities:

| Community | Focus | Notes |
|---|---|---|
| IT-ISAC | IT sector threat sharing | Primary venue for NVIDIA product threats |
| AI Safety ISAC (emerging) | AI infrastructure security | Nascent but growing |
| MS-ISAC | State/local government | Relevant if NVIDIA deployed in government |
| FS-ISAC | Financial sector | Relevant if protecting financial AI infrastructure |
| H-ISAC | Healthcare | Relevant for healthcare AI deployments |
| FIRST | Global CSIRT/PSIRT sharing | Framework and trust community |

Share: IoCs (STIX), ATT&CK mappings, hunting hypotheses.
Receive: Early warning of exploitation, actor campaigns, novel TTPs.

---

## 14. Detection and Hunting Integration

### 14.1 Hunting Hypotheses (Prioritised)

**HH-1: Container Escape via NVIDIA Container Toolkit (CVE-2025-23266)**
Priority: CRITICAL

Required telemetry: EDR, eBPF (Falco/Tetragon), container runtime logs

Detection logic:
```yaml
# Falco rule
- rule: NVIDIA Container Toolkit LD_PRELOAD Abuse
  desc: Detects anomalous LD_PRELOAD usage during nvidia-container-toolkit hook phase
  condition: >
    spawned_process and
    proc.name in (nvidia-container-runtime-hook, nvidia-ctk) and
    env.name = "LD_PRELOAD" and
    not env.value pmatch (/usr/lib/x86_64-linux-gnu/*, /usr/local/lib/*)
  output: >
    Suspicious LD_PRELOAD in NVIDIA hook (proc=%proc.name env=%env.value
    container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [T1611, T1574.006, CVE-2025-23266]
```

**HH-2: NVUE Command Injection (CVE-2025-33179/33181)**
Priority: HIGH

Required telemetry: auditd on switch, NVUE application logs, centralised syslog

Detection logic:
```
# Sigma rule concept
title: NVUE REST API Command Injection Attempt
detection:
  selection:
    http.uri|contains: '/api/v1/'
    http.request.body|re: '[;&|`$(){}]'
    http.target_service: 'nvued'
  filter:
    http.source_ip|cidr: '10.0.0.0/8'  # adjust to your management CIDR
  condition: selection and not filter
falsepositives:
  - Poorly formatted automation scripts
level: high
tags: T1059.004, T1190
```

**HH-3: BlueField BMC Covert Access**
Priority: HIGH

Required telemetry: DOCA Argus, BMC auth logs, OOB network flow logs

Detection logic:
```
# Splunk SPL concept
index=bluefield sourcetype=bmc_auth
| stats count by src_ip, action, user
| where action="failed" AND count > 5
| join src_ip [
    search index=network_flows dest_port=22 dest_category="bluefield_mgmt"
    | stats count by src_ip
    | where NOT cidrmatch("10.x.x.0/24", src_ip)  # management VLAN
  ]
| alert if count > 0
```

**HH-4: Volt Typhoon LOTL on Cumulus Linux / NVOS**
Priority: HIGH

Required telemetry: auditd, Zeek network logs, NetFlow

Indicators:
- Use of built-in tools (netstat, ip, arp, ping) in unusual sequences from low-privilege accounts
- BGP route table modifications outside change windows
- SNMP walks from unexpected source IPs
- Large log file deletion or log truncation events
- Scheduled task/cron creation by non-admin accounts

**HH-5: Stolen NVIDIA Certificate Abuse**
Priority: MEDIUM (ongoing; no NVIDIA-specific infrastructure required)

Required telemetry: Endpoint EDR, Windows driver installation events

Detection logic:
```powershell
# Windows Event Log
Get-WinEvent -FilterHashtable @{
  LogName='System'; Id=7045
} | Where-Object {
  $_.Message -match 'NVIDIA' -and
  $_.Message -match '(expired|revoked|2022)'
}
```

Check certificate thumbprints associated with LAPSUS$-stolen NVIDIA certificates
against your certificate trust store and endpoint driver inventory.

### 14.2 Detection Coverage Map

Maintain an ATT&CK Navigator layer showing which techniques you have detection coverage for.
Review after each new PSIRT bulletin to identify gaps.

**Priority gaps to close first (as of 2026 baseline):**
- T1014 (Rootkit) — no mature tooling for DPU firmware rootkit detection
- T1210 (Exploit Remote Services via RDMA) — requires RDMA-aware network monitoring
- T1195 (Supply Chain Compromise) — partial coverage via SBOM scanning

### 14.3 Indicator Lifecycle Management

IoCs decay. Manage them with explicit TTL:

| IoC type | Default TTL | Rationale |
|---|---|---|
| IP address | 7 days | Dynamic allocation; rotate quickly |
| Domain | 30 days | More persistent but still rotated |
| File hash (MD5/SHA1) | 6 months | Malware often repacked |
| File hash (SHA256) | 12 months | Harder to change without functional change |
| CVE (unpatched) | Until patch deployed + 30 days | Ongoing exploit risk |
| ATT&CK technique | Permanent | Techniques persist across campaigns |

---

## 15. Metrics and Programme Maturity

### 15.1 Key Performance Indicators

**Collection metrics:**
- Mean time from NVIDIA bulletin publication to MISP ingest: target < 4 hours
- PIR coverage rate: % of PIRs with active collection against them
- Source diversity index: number of distinct source categories feeding each PIR
- False positive rate from automated feeds: target < 10%

**Analysis metrics:**
- Mean time to intelligence product from triggering event: target < 24 hours (High/Critical)
- PIR answer rate: % of PIRs answered per quarter
- Analytic accuracy: tracked via post-incident review
- Coverage of ATT&CK techniques relevant to NVIDIA threats: track via Navigator

**Operational impact metrics:**
- Patch time reduction attributable to early CTI warning (vs. standard NVD lag)
- Number of detections fired that were CTI-informed
- Number of hunting leads generated per quarter
- Threat hunts completed per quarter

### 15.2 Maturity Model

| Level | Description | Indicators |
|---|---|---|
| 1 — Initial | Ad hoc; reactive; no formal process | Responding to public CVEs after the fact |
| 2 — Developing | Basic feed ingestion; some PIRs; limited analysis | NVD + PSIRT monitoring; weekly digest |
| 3 — Defined | Formal PIRs; multi-source collection; structured analysis products | Full PIR set; MISP/OpenCTI deployed; ATT&CK mapping |
| 4 — Managed | Measured; darknet coverage; actor tracking; hunting integration | All 9 source categories active; detection feedback loop |
| 5 — Optimising | Predictive; ISAC leadership; automated enrichment; closed-loop | Forward-looking research coverage; ISAC sharing; SLA metrics met |

---

## 16. Reference Tables

### 16.1 NVIDIA Product Version Baseline (June 2026)

| Product | Minimum secure version | Key CVEs requiring patch | Bulletin reference |
|---|---|---|---|
| BlueField DPU firmware | GA ≥ 45.1020 / LTS ≥ 35.4554 | CVE-2025-23256 | NVIDIA Security Bulletin 5655 |
| DOCA collectx-dpeserver | ≥ 2.5.4 (LTS) / ≥ 2.9.3 (GA) | CVE-2025-23257/23258 | NVIDIA Security Bulletin 5655 |
| Cumulus Linux | ≥ 5.14 (GA) / ≥ 5.11.4 (LTS) | CVE-2025-33179, CVE-2025-33181 | NVIDIA Security Bulletin 5722 |
| NVOS (GB200/GB300/IB XDR) | Check bulletin 5722 version matrix | CVE-2025-33179, CVE-2025-33181 | NVIDIA Security Bulletin 5722 |
| NVIDIA Container Toolkit | ≥ 1.17.8 | CVE-2025-23266 | NVIDIA Security Bulletin 5659 |
| GPU Operator | ≥ 25.3.0 | CVE-2025-23266 | NVIDIA Security Bulletin 5659 |
| Jetson (JetPack) | ≥ 35.6.4 | CVE-2026-24148 | NVIDIA Security Bulletin 5797 |
| Mellanox OS / ONYX / Skyway | ≥ 3.11.2002 | CVE-2024-0101 | NVIDIA Security Bulletin 5559 |
| Linux GPU Display Driver | ≥ 596.36 | CVE-2026-24187 | NVIDIA Security Bulletin 5821 |

### 16.2 Quick Reference: Source Priority by PIR

| PIR | Top 3 sources | Tool/platform |
|---|---|---|
| PIR-1 (Active exploit dev) | NVIDIA PSIRT GitHub, Recorded Future, Shodan | OpenCTI + RF |
| PIR-2 (Volt/Salt Typhoon expansion) | CISA advisories, Mandiant, Lumen | MISP + TheHive |
| PIR-3 (NVIDIAScape in-the-wild) | Cloud provider blogs, Falco telemetry, Cybersixgill | Falco + Splunk |
| PIR-4 (APT41 IP targeting) | Mandiant, DOJ filings, Recorded Future | Mandiant Advantage |
| PIR-5 (Supply chain) | OSV, Snyk, NVIDIA SBOM | Dependency-Track + Grype |
| PIR-6 (Side-channel research) | arXiv, USENIX, IEEE S&P | RSS + Scholar Alerts |
| PIR-7 (Iran/Israel targeting) | CERT-IL, Mandiant Iran, ClearSky | OpenCTI + Recorded Future |

### 16.3 ATT&CK Navigator Layer — NVIDIA Threat Model

Download the MITRE ATT&CK Navigator (`github.com/mitre-attack/attack-navigator`) and
create a layer file with the following techniques highlighted:

**Red (confirmed vendor CVE evidence):**
T1190, T1068, T1059.004, T1611, T1574.006, T1552, T1499

**Orange (strong sector/analogue evidence):**
T1195, T1021, T1078, T1003, T1553.002, T1567

**Yellow (research / emerging):**
T1014, T1210, T1622

### 16.4 Escalation Thresholds

| Trigger | Escalation target | Timeframe |
|---|---|---|
| CISA KEV addition for any NVIDIA Tier 1/2 CVE | CISO + VulnMgmt + SOC | Immediate (< 1 hour) |
| Credible darknet PoC claim for NVIDIA networking CVE | CISO + PSIRT + VulnMgmt | < 2 hours |
| Confirmed in-the-wild exploitation (any source) | Incident commander + CISO | Immediate |
| New NVIDIA PSIRT bulletin (CVSS ≥ 8.0, Tier 1/2 product) | VulnMgmt + SOC | < 4 hours |
| New NVIDIA PSIRT bulletin (CVSS < 8.0 or Tier 3–5) | VulnMgmt | Next business day |
| CISA/NSA advisory naming actor targeting network device class | CTI lead + Architecture | < 4 hours |
| Credential dump containing nvidia.com domain | Identity team + CISO | < 2 hours |

---

*Guide version 1.0 — Baseline date: June 2026*
*Review cadence: Quarterly or upon major NVIDIA product landscape change*
*Owner: [CTI Programme Lead]*
