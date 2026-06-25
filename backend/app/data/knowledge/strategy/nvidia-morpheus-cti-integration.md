# NVIDIA Morpheus — Integration with the NVIDIA Product CTI Strategy

> **Document purpose:** Defines where and how NVIDIA Morpheus enhances each layer of
> the CTI strategy defined in `nvidia-cti-strategy-guide.md`. Covers detection
> engineering, threat hunting, data collection, and analysis workflows.
>
> **Morpheus version baseline:** v25.06.00 (Apache 2.0)
> **Companion documents:** `nvidia-cti-strategy-guide.md`,
> `references/vendor-reports/nvidia-morpheus-framework-documentation.md`

---

## Why Morpheus is Strategically Relevant to This CTI Programme

The CTI strategy established that NVIDIA's most exposed trust boundaries are:
- Management interfaces (NVUE, BMC, DOCA APIs)
- Network fabric (Cumulus Linux, NVOS, Spectrum switches)
- Container isolation boundary (Container Toolkit)
- DPU control plane (BlueField, DOCA services)

Morpheus uniquely addresses these surfaces because:

1. **It runs on the same hardware it monitors.** The DOCA Source Stage captures packets
   directly from BlueField/ConnectX NICs via DOCA GPUNetIO — wire speed, no CPU
   bottleneck, invisible to a compromised host OS.

2. **It is the only security framework with a native BlueField DPU integration.**
   The `DocaSourceStage` captures live TCP/UDP from the fabric layer where our
   highest-priority threats (Volt Typhoon LOTL, RDMA exfiltration, NVUE injection)
   actually transit.

3. **It bridges DOCA Argus telemetry to SIEM.** Morpheus can consume DOCA Argus
   process introspection output and stream structured detection events to
   Elasticsearch or Kafka — closing the loop between BlueField-native detection
   and enterprise security operations.

4. **Its pre-trained models map directly to confirmed NVIDIA CVE attack patterns.**
   The SID model detects the exact credential/key leakage confirmed in CVE-2025-33179/
   33181 (Cumulus password hash leakage). The DLP pipeline detects AI model weight
   exfiltration that would follow a BlueField compromise. The DFP model baselines
   the legitimate admin behaviour Volt Typhoon mimics via LOTL.

---

## Architecture: Morpheus in the NVIDIA CTI Stack

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        COLLECTION LAYER                                 │
│                                                                         │
│  BlueField DPU                  Cumulus Linux / NVOS        GPU Hosts   │
│  ┌──────────────┐               ┌──────────────────┐      ┌──────────┐  │
│  │ DOCA Argus   │               │  Syslog / NVUE   │      │ nv-smi   │  │
│  │ DOCA Vault   │               │  API access logs │      │ AppShield│  │
│  │ BMC auth logs│               │  BGP change logs │      │ telemetry│  │
│  └──────┬───────┘               └────────┬─────────┘      └────┬─────┘  │
│         │ DOCA GPUNetIO                  │ Kafka/Syslog        │        │
│         ↓                               ↓                     ↓        │
└─────────┼───────────────────────────────┼─────────────────────┼────────┘
          ↓                               ↓                     ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                    MORPHEUS PIPELINE LAYER                              │
│                                                                         │
│  Pipeline 1             Pipeline 2             Pipeline 3              │
│  ┌─────────────┐        ┌──────────────┐       ┌──────────────┐        │
│  │ DOCA Source │        │ Kafka Source │       │ File Source  │        │
│  │ SID Model   │        │ DFP Model    │       │ ABP Model    │        │
│  │ DLP Pipeline│        │ Log Parsing  │       │ Ransomware   │        │
│  └──────┬──────┘        └──────┬───────┘       └──────┬───────┘        │
│         └──────────────────────┴──────────────────────┘                │
│                                ↓                                        │
│                    Triton Inference Server                              │
│                    (GPU-accelerated inference)                          │
└─────────────────────────────────────────────────────────────────────────┘
                                 ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                       OUTPUT / ANALYSIS LAYER                          │
│                                                                         │
│  Elasticsearch/SIEM    Kafka alert topics    Vector DB + LLM/RAG       │
│  (OpenCTI / MISP)      (SOC real-time)       (CTI analyst queries)     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Use Case 1: Real-Time Sensitive Data Detection in AI Fabric Traffic

**Morpheus pipeline:** DOCA Source → SID Model
**Addresses PIR-1, PIR-5**

### What it does

The `DocaSourceStage` captures live TCP/UDP packets from a BlueField-connected
ConnectX NIC via DOCA GPUNetIO. Packets are passed directly into GPU memory
(bypassing host OS), tokenised, and scored by the `sid-minibert` model in real-time.

The SID model classifies payloads against 10 sensitive data categories. In the NVIDIA
CTI context, the most critical are:
- **Secret keys / API keys** — NVIDIA NGC tokens, DOCA service accounts
- **Passwords** — the exact category leaked in CVE-2025-33179/33181 (Cumulus/NVOS
  NVUE password hashes exposed in logs and potentially in management traffic)
- **Usernames / credentials** — BlueField BMC admin credentials in OOB management traffic

### Why this is critical

Unencrypted management traffic on the OOB network (IPMI, NVUE REST, BMC API) may
contain credentials in plaintext or in formats detectable by SID. A compromised
switch or DPU logging credentials in management traffic would be caught before
those credentials are used for lateral movement.

This is also the primary detection path for **post-LAPSUS$ certificate abuse**:
if a compromised host sends credentials over the fabric to an attacker-controlled
endpoint, SID catches the exfiltration in the RDMA/RoCE traffic stream.

### Deployment requirements

```bash
# Run on BlueField-equipped server with ConnectX NIC
python examples/doca/run_tcp.py \
    --nic_addr cc:00.1 \    # ConnectX PCIe address
    --gpu_addr cf:00.0      # Co-located GPU PCIe address

# Output alerts to Kafka for SIEM ingestion
# Add WriteToKafkaStage after inference stage
```

### Detection mapping

| ATT&CK Technique | Morpheus Detection |
|---|---|
| T1552 — Unsecured Credentials | SID flags credential patterns in network payload |
| T1040 — Network Sniffing | Baseline: SID should not see credentials in fabric traffic |
| T1567 — Exfiltration Over Web Service | SID + DLP detect sensitive data leaving fabric |

---

## Use Case 2: Data Loss Prevention for AI Model Weights

**Morpheus pipeline:** DOCA Source / Kafka Source → DLP Pipeline (Regex + GLiNER)
**Addresses PIR-4, PIR-5**

### What it does

The DLP pipeline runs a two-stage detection:
1. Regex pre-filter: high-recall fast scan for IP addresses, API keys, URLs, account numbers
2. GLiNER semantic validation: confirms context — is this a real credential or a false positive?

Applied to AI fabric traffic via DOCA, this pipeline detects:
- AI model weight exfiltration via RDMA (even unencrypted RoCEv2 streams)
- NVIDIA NGC API token leakage in API calls captured in network traffic
- Training data exfiltration through AIStore (relevant post CVE-2025-33185 AuthN bypass)

### APT41 / State Actor Relevance

APT41's primary motivation is IP theft — specifically AI model architectures and weights.
A compromised host in a multi-tenant GPU environment (post NVIDIAScape CVE-2025-23266
container escape) would attempt to exfiltrate model weights via network.

DLP running on BlueField (below the compromised host) sees this exfiltration and
cannot be disabled by an attacker who only has host OS access.

### Pipeline configuration

```python
# DLP on RDMA/storage traffic - key entities to detect
DETECTED_ENTITIES = [
    "api_key",       # NVIDIA NGC tokens: nvcr.io auth tokens
    "password",      # Service account passwords
    "ip_address",    # Unexpected external destinations
    "url",           # C2 callback URLs in exfil traffic
    "account_number" # Financial data if deployed in finance sector
]

# Alert threshold: any credential/key in outbound traffic = HIGH severity
```

---

## Use Case 3: User and Entity Behavior Analytics (UEBA) for Management Interfaces

**Morpheus pipeline:** Kafka/File Source → Digital Fingerprinting (DFP) Model
**Addresses PIR-2 (Volt Typhoon LOTL)**

### What it does

The DFP model trains an Autoencoder on a baseline period of legitimate admin activity,
then continuously scores new activity against that baseline. Anomaly scores flag
sessions that deviate from established patterns.

Applied to NVIDIA management surfaces:

| Log source | What DFP baselines | What it detects |
|---|---|---|
| NVUE REST API access logs | Normal admin commands, frequency, timing | Volt Typhoon LOTL — legitimate account making unusual NVUE calls |
| BlueField BMC auth logs | Normal admin login times, source IPs, command sequences | Attacker using stolen credentials from unusual source |
| DOCA Argus process telemetry | Normal DOCA service process trees | New processes spawning from DOCA services |
| Cumulus Linux SSH sessions | Normal interactive session patterns | Hands-on-keyboard attacker session (unusual command sequence) |

### Volt Typhoon Detection Rationale

Volt Typhoon's defining characteristic is using **valid accounts with LOTL techniques**.
Traditional signature-based detection fails because:
- No malware is deployed
- Commands used are standard Linux/network tools
- Valid credentials are used

DFP is purpose-built for this. The Autoencoder learns what legitimate admin sessions
look like and flags deviations — even if every individual command is legitimate.

### CloudTrail analog for on-premises NVIDIA environments

The DFP example uses AWS CloudTrail. For on-premises NVIDIA deployments, the equivalent
input is:
- NVUE audit log (`/var/log/nvue/audit.log`)
- BlueField DOCA service event log
- Cumulus Linux auditd log
- Zeek connection log for management VLAN

### Implementation note

DFP requires a clean baseline period. For NVIDIA environments:
- Baseline period: 14–30 days of verified-clean management activity
- Retrain quarterly or after major configuration changes
- Separate models per device type (Cumulus switch, BlueField DPU, ConnectX host)

---

## Use Case 4: GPU Malware and Cryptominer Detection

**Morpheus pipeline:** File/Stream Source → Anomalous Behavior Profiling (ABP) Model
**Addresses post-compromise detection of LAPSUS$-style supply chain attacks**

### What it does

The ABP XGBoost model scores nvidia-smi telemetry (GPU utilization, memory, power,
temperature, process list) against a baseline of legitimate ML/DL workloads. Any
process pattern matching GPU malware signatures triggers an alert.

### NVIDIA CTI relevance

Post-compromise scenarios where GPU malware is relevant:
1. Supply chain compromise (malicious DOCA Debian package) installs cryptocurrency
   miner on DPU ARM cores
2. Container escape (CVE-2025-23266 NVIDIAScape) allows attacker to deploy GPU miner
   on the host from within a container
3. Compromised NGC container image contains GPU-resident backdoor or RAT

### Pipeline configuration

```bash
# ABP using nvidia-smi data
python examples/abp_nvsmi_detection/run_abp_nvsmi_detection_pipeline.py \
    --input_file ./examples/data/nvsmi.jsonlines \
    --output_file /tmp/abp_output.jsonlines \
    --server_url localhost:8001 \
    --model_name abp-nvsmi-xgb
```

### Integration with DOCA Argus

DOCA Argus provides process introspection at the DPU level. Combining:
- DOCA Argus: detects new process spawning on DPU ARM cores
- ABP: scores GPU telemetry for cryptomining patterns
- DFP: flags deviation from baseline process behaviour

Creates a multi-layer detection that is resistant to evasion at any single layer.

---

## Use Case 5: NVUE and Switch Log Intelligence

**Morpheus pipeline:** Syslog/Kafka Source → Log Parsing (cyBERT) → Elasticsearch
**Addresses PIR-1 (NVUE exploit detection), PIR-2 (Volt Typhoon)**

### What it does

The cyBERT log parsing model (BERT-base cased + NER layer) converts raw unstructured
syslog lines into structured JSON with named entities extracted. This enables:
- Machine-searchable log data from Cumulus Linux / NVOS
- Structured NVUE command audit trail
- BGP route change events with attributed actor, time, delta

### Retraining for NVIDIA-specific log formats

The default model is trained on Apache web logs. For NVIDIA environments, retrain on:

```python
# Target log formats for retraining:
LOG_FORMATS = [
    "Cumulus Linux NVUE REST API access log",
    "NVOS management interface audit log",
    "DOCA service syslog",
    "BlueField BMC audit trail",
    "Mellanox ONYX/MLNX-OS management log"
]
# Training data: use existing Cumulus/NVOS log archives from your environment
# Label entities: username, IP, command, timestamp, result, CVE-relevant_keyword
```

### Detection logic after parsing

Once logs are structured, standard SIEM rules detect CVE-2025-33179/33181 patterns:

```
# Structured log alert: NVUE injection attempt
SELECT * FROM nvue_logs
WHERE command_field MATCHES REGEX '[;&|`$(){}]'
  AND source_ip NOT IN management_vlan_cidrs
  AND timestamp > NOW() - INTERVAL 1 HOUR
```

### Pipeline

```
Syslog (UDP 514) → Kafka topic "cumulus-syslog"
    → Morpheus KafkaSourceStage
    → DeserializeStage
    → PreprocessNLPStage (BERT tokenization)
    → TritonInferenceStage (log-parsing-onnx)
    → PostprocessStage (entity extraction)
    → WriteToElasticsearchStage (index: nvidia-switch-logs)
    → Kibana / OpenSearch dashboard
```

---

## Use Case 6: Ransomware Protection of AI Workloads

**Morpheus pipeline:** AppShield Source → Ransomware Detection Model
**Addresses ransomware-as-initial-access and data destruction scenarios**

### What it does

AppShield captures snapshots of running processes (memory maps, syscall patterns,
file access patterns) at configurable intervals. The Random Forest model scores
sliding windows of 3/5/10 snapshots for ransomware activity patterns.

### NVIDIA AI environment relevance

Ransomware groups are increasingly targeting AI/HPC environments to:
- Encrypt training datasets (ransom leverage)
- Destroy model checkpoints mid-training
- Use AI cluster GPU resources for cryptomining while extorting via data encryption

The DBIR 2025 (downloaded, `references/government/verizon-dbir-2025.pdf`) documents
that ransomware now appears in 44% of breaches, with exploitation as a top initial
access vector. NVIDIA CVEs (NVIDIAScape, NVUE injection) are plausible ransomware
initial access paths.

### Pipeline configuration

```bash
python examples/ransomware_detection/run.py \
    --server_url=localhost:8000 \
    --sliding_window=3 \
    --model_name=ransomw-model-short-rf \
    --input_glob=/var/appshield/snapshots/*/snapshot-*/*.json \
    --output_file=/var/log/morpheus/ransomware_alerts.jsonlines
```

---

## Use Case 7: LLM-Assisted CTI Analysis

**Morpheus pipeline:** Vector DB → LLM/RAG Pipeline
**Addresses analyst workflow for all PIRs**

### What it does

The `examples/llm/` pipeline builds a RAG (Retrieval-Augmented Generation) system
over security data indexed in a vector database. Analysts can query the system in
natural language and receive answers grounded in actual collected intelligence.

### Integration with the NVIDIA CTI Reference Library

The reference collection in `references/` (42 files, 17MB) can be indexed into
a vector database and queried via Morpheus LLM pipeline:

```python
# Index all reference documents into Milvus/Faiss
# Sources to index:
REFERENCE_SOURCES = [
    "references/nvidia-psirt/*.md",       # CVE analysis files
    "references/threat-actors/*.md",       # Actor profiles
    "references/cve/*.json",               # NVD raw JSON
    "references/academic/*.pdf",           # Research papers
    "references/vendor-reports/*.md"       # Architecture docs
]

# Example analyst queries via LLM/RAG:
EXAMPLE_QUERIES = [
    "What BlueField firmware versions are affected by CVE-2025-23256?",
    "Which Volt Typhoon TTPs are most relevant to NVUE management interfaces?",
    "What detection rules exist for NVIDIAScape container escapes?",
    "Summarise all NVIDIA PSIRT bulletins affecting Tier 1 products in 2025-2026",
    "What indicators distinguish Volt Typhoon activity on a Cumulus Linux switch?"
]
```

### Vector DB + DOCA real-time integration

The `examples/doca/vdb_realtime/` example combines:
- DOCA Source Stage: live packet capture from BlueField/ConnectX
- Vector DB: stores packet metadata and embeddings
- LLM: enables "what unusual traffic did we see in the last hour?" style queries

This creates an AI-native network forensics capability directly on the DPU.

---

## PIR-to-Morpheus Pipeline Mapping

| PIR | Morpheus Pipeline | Model(s) | Alert output |
|---|---|---|---|
| PIR-1 — Active exploit dev | DOCA → SID; Kafka → DLP | SID-minibert, GLiNER | Elasticsearch, Kafka |
| PIR-2 — Volt Typhoon expansion | Syslog → Log Parsing + DFP | cyBERT, Autoencoder+FFT | SIEM alert |
| PIR-3 — NVIDIAScape in-the-wild | DOCA → SID; Host → ABP | SID, XGBoost ABP | SIEM + PagerDuty |
| PIR-4 — APT41 IP targeting | DOCA → DLP; Email → Phishing | GLiNER DLP, BERT phishing | SIEM + analyst queue |
| PIR-5 — Supply chain compromise | AppShield → Ransomware; Host → ABP | RF ransomware, ABP | Critical alert |
| PIR-6 — Side-channel research | GPU telemetry → ABP | XGBoost ABP | Research monitoring |
| PIR-7 — Iran/Israel targeting | Email → Phishing; Zeek → DFP | BERT phishing, DFP | SIEM |

---

## ATT&CK Coverage Provided by Morpheus

| Technique | Morpheus Pipeline | Detection method |
|---|---|---|
| T1190 — Exploit Public-Facing App | Log Parsing (NVUE logs) | Structured injection pattern detection |
| T1611 — Escape to Host | DOCA SID + ABP | LD_PRELOAD in network payload; GPU utilisation spike |
| T1552 — Unsecured Credentials | DOCA SID | Credential patterns in fabric traffic |
| T1078 — Valid Accounts | DFP (UEBA) | Behavioral deviation from admin baseline |
| T1014 — Rootkit | ABP + DOCA Argus feed | Anomalous process on DPU ARM cores |
| T1567 — Exfiltration Over Web Service | DLP | Sensitive data in outbound traffic |
| T1499 — Endpoint DoS | DFP + Log Parsing | Traffic surge patterns, NVUE flood |
| T1059.004 — Unix Shell | Log Parsing | Shell metacharacters in command fields |
| T1195 — Supply Chain Compromise | AppShield Ransomware + ABP | Anomalous process post-update |

---

## Deployment Architecture Recommendation

### Tier 1: BlueField DPU Layer (Highest Priority)

Deploy **Morpheus DOCA container** on a dedicated analysis server with:
- BlueField-2/3 DPU as network tap (DOCA GPUNetIO)
- NVIDIA A30/A100/H100 GPU for inference
- Kafka output to enterprise SIEM

Pipelines to run:
- SID on management VLAN TCP traffic
- DLP on storage/RDMA traffic (detect model exfiltration)
- DFP baseline on NVUE API access logs

### Tier 2: Fabric / Switch Layer

Deploy **Morpheus on log aggregation server** with:
- Cumulus Linux/NVOS syslog via Kafka
- Log Parsing (cyBERT) pipeline
- DFP on NVUE session data

### Tier 3: Compute / GPU Hosts

Deploy **Morpheus standard container** with:
- ABP on nvidia-smi telemetry (GPU malware)
- AppShield Ransomware detection
- Container runtime log monitoring (NVIDIAScape detection)

### Reference Architecture

```
BlueField DPU (OOB management network tap)
    ↓ DOCA GPUNetIO
[Morpheus DOCA Server]
    SID Pipeline → Kafka → SIEM "nvidia-fabric-credentials-alert"
    DLP Pipeline → Kafka → SIEM "nvidia-model-exfiltration-alert"
    ↓
[Morpheus Log Analysis Server]
    cyBERT Log Parsing (Cumulus/NVOS/DOCA logs)
    DFP (NVUE session baseline)
    → Elasticsearch index: "nvidia-switch-intelligence"
    ↓
[GPU Host Monitoring]
    ABP (nvidia-smi) → SIEM "nvidia-gpu-anomaly-alert"
    Ransomware detection → SIEM "nvidia-ransomware-alert"
    ↓
[CTI Analyst Workstation]
    Morpheus LLM/RAG → indexed reference library
    Natural language queries over all NVIDIA CTI data
```

---

## Operational Workflow Integration

### 1. Alert Triage Workflow

```
Morpheus Alert (Kafka)
    ↓
TheHive Case Creation (auto-enrichment via Cortex)
    ↓
MISP / OpenCTI IoC lookup (is this actor-attributed?)
    ↓
ATT&CK Navigator update (confirm/deny technique coverage)
    ↓
PIR status update (does this answer an open PIR?)
    ↓
Escalation per threshold table (nvidia-cti-strategy-guide.md §13.4)
```

### 2. Threat Hunting Workflow

```
Morpheus LLM/RAG query:
  "Show me all NVUE API calls from unusual source IPs in the last 7 days"
    ↓
Review structured cyBERT output in Elasticsearch
    ↓
Correlate with DFP anomaly scores for same users/IPs
    ↓
Cross-reference against Volt Typhoon TTP profile
  (references/threat-actors/volt-typhoon-full-profile.md)
    ↓
Generate hunting hypothesis and run SIEM hunt
```

### 3. CVE Response Workflow

```
New NVIDIA PSIRT bulletin published (GitHub webhook → MISP)
    ↓
Morpheus LLM/RAG: "What does CVE-XXXX affect in our environment?"
    ↓
Update DFP baseline if new management interface patched
    ↓
Retrain SID/DLP if new credential exposure vector identified
    ↓
Add Morpheus detection rule for new attack pattern
```

---

## What Morpheus Cannot Do (Boundaries)

| Limitation | Impact | Mitigation |
|---|---|---|
| DOCA Source Stage is Early Access | Limited production deployment | Use Kafka/Zeek as initial alternative; plan for DOCA production in 2026 |
| DFP requires clean baseline period | Cannot be deployed mid-incident | Establish baseline in lab before production deployment |
| SID model trained on web API/PCAP payloads | May miss NVIDIA-specific credential formats | Fine-tune SID on NVIDIA-specific data (NVUE tokens, NGC API keys) |
| cyBERT trained on Apache logs | NVUE/Cumulus logs require retraining | Collect 1000+ labelled Cumulus syslog entries for fine-tuning |
| ABP requires nvidia-smi access | Does not monitor DPU ARM processes | Combine with DOCA Argus process telemetry |
| No InfiniBand native support (yet) | Cannot inspect raw IB traffic | Use RoCEv2 (Ethernet-encapsulated) as primary monitoring surface |
| LLM queries are only as good as indexed data | Stale intelligence = stale answers | Automate nightly re-indexing of reference library |

---

## Quick Start: Minimum Viable Morpheus Deployment for NVIDIA CTI

If resources are limited, deploy in this sequence:

**Week 1:** GPU telemetry monitoring (zero new infrastructure needed)
```bash
# ABP on all GPU hosts — detects post-compromise GPU abuse
morpheus run pipeline-fil \
    --model_name abp-nvsmi-xgb \
    --input_type nvsmi \
    --output_file /var/log/morpheus/abp-alerts.jsonlines
```

**Week 2:** Log intelligence (cyBERT on existing syslog)
```bash
# Log parsing on Cumulus/NVOS syslog
# Requires Triton server with log-parsing-onnx model
```

**Week 3:** Behavioral baseline (DFP on management access logs)
```bash
# Start 30-day baseline collection on NVUE access logs
# Deploy training at end of baseline period
```

**Month 2:** DOCA live traffic analysis (requires BlueField hardware + DOCA container access)

**Month 3:** Full LLM/RAG over CTI reference library

---

*Document version 1.0 — June 2026*
*Cross-reference: nvidia-cti-strategy-guide.md, references/INDEX.md*
