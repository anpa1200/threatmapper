# NVIDIA Morpheus — Framework Documentation Reference
Source: GitHub repo nv-morpheus/Morpheus (Apache 2.0), NGC, NVIDIA Developer Docs
Latest version: v25.06.00 | GitHub: github.com/nv-morpheus/Morpheus

---

## What Morpheus Is

"An open AI application framework that provides cybersecurity developers with a highly
optimized AI framework and pre-trained AI capabilities that allow them to instantaneously
inspect all IP traffic across their data center fabric."

Built on:
- NVIDIA RAPIDS (cuDF, cuML) for GPU-accelerated dataframes
- NVIDIA Triton Inference Server for model serving
- Python (54.9%) + C++/CUDA (19%) core
- Apache Kafka, Elasticsearch integrations

---

## Pipeline Architecture

Morpheus uses a linear, modular stage-based pipeline:

```
Input Stage → Processing Stage(s) → Inference Stage → Postprocessing → Output Stage
    ↓                ↓                    ↓                 ↓               ↓
  DOCA/Kafka     NLP/FIL preproc      Triton Server      Filtering      Elasticsearch
  File/HTTP      Deserialization      (ONNX/TRT/PyT)     Scoring         Kafka topic
  CloudTrail     Deduplication        Custom models      Thresholding    Vector DB
  Zeek logs      Feature eng.         GPU inference      Alert gen.      File output
```

---

## Pre-Trained Models (Production Ready)

### 1. Sensitive Information Detection (SID)
- **Architecture:** BERT-mini (compact, 4-layer, 256-hidden) — fast inference
- **Input:** English text from PCAP payloads, network traffic, log entries
- **Output:** Multi-label classification across 10 sensitive data categories:
  - AWS credentials, GitHub credentials, API/secret keys
  - Passwords, usernames, email addresses
  - Government ID numbers, bank accounts, credit card numbers
  - Full names, phone numbers, physical addresses
- **Training:** 2 million synthetic PCAP payloads mimicking web API and env var data
- **Model file:** `sid-minibert-20230424.onnx`
- **Use with DOCA:** Can run on live TCP stream from BlueField/ConnectX

### 2. Phishing Email Detection
- **Architecture:** BERT-base uncased (12-layer)
- **Input:** Full email text as string
- **Output:** Binary — phishing/spam vs. legitimate
- **Training:** ~5000 SMS messages from UCI SMS Spam Collection dataset

### 3. Anomalous Behavior Profiling (ABP)
- **Architecture:** XGBoost gradient boosted trees
- **Input:** nvidia-smi telemetry data (GPU utilization, memory, power, temperature)
- **Output:** Binary — anomalous (cryptominer/GPU malware) vs. benign (ML/DL training)
- **Training:** ~1000 labeled nvidia-smi logs from GPU malware vs. legitimate workloads
- **Two variants:** PCAP-based and nvidia-smi-based detection

### 4. Digital Fingerprinting (DFP)
- **Architecture:** Autoencoder + Fast Fourier Transform (FFT) ensemble
- **Input:** AWS CloudTrail logs, authentication event logs, user activity logs
- **Output:** Anomaly score (Autoencoder reconstruction loss) + binary time-series anomaly flag
- **Training:** Baseline benign user/entity activity period (unsupervised)
- **Use case:** UEBA — detects human-to-machine or machine-to-human behavioral shifts

### 5. Flexible Log Parsing (cyBERT)
- **Architecture:** BERT-base cased with NER classification layer
- **Input:** Raw unstructured log lines (tested on Apache web logs)
- **Output:** Structured JSON with named entities extracted
- **Training:** 1000 parsed Apache web logs from Loghub dataset
- **Extensible:** Can be retrained on Cumulus Linux, NVOS, DOCA syslog formats

### 6. Data Loss Prevention (DLP) — Hybrid Pipeline
- **Architecture:** Regex pre-filter + GLiNER (semantic NER model)
- **Input:** Text documents, CSV with source_text field, data streams
- **Detected categories:** SSN, credit cards, phone numbers, email addresses, IP addresses,
  API keys, passwords, URLs, medical records, insurance IDs, account numbers
- **Design:** High-recall regex → high-precision LLM validation (2-stage pipeline)

### 7. Fraud Detection (GNN)
- **Architecture:** GraphSAGE (HinSAGE for heterogeneous graphs) + XGBoost
- **Input:** Transaction graph (transaction, client, merchant nodes)
- **Output:** Fraud probability score per transaction
- **Use case:** Financial fraud; adaptable to AI resource abuse detection

### 8. Ransomware Detection (AppShield)
- **Architecture:** Random Forest (short/medium/long variants)
- **Input:** AppShield process snapshots (sliding window of 3/5/10 snapshots)
- **Output:** Ransomware probability score
- **Model:** `ransomw-model-short-rf` (Triton-served)

---

## Key Pipeline Examples

### DOCA Example (Most NVIDIA-Product Relevant)
**Files:** `examples/doca/run_tcp.py`, `run_udp_raw.py`, `run_udp_convert.py`

```python
# TCP traffic → SID detection pipeline
# DocaSourceStage captures live packets from BlueField/ConnectX via DOCA GPUNetIO
# sid-minibert model runs inference on packet payloads in real-time

python examples/doca/run_tcp.py \
    --nic_addr cc:00.1 \   # ConnectX PCIe address
    --gpu_addr cf:00.0     # GPU PCIe address
```

Pipeline stages:
```
DocaSourceStage (BlueField/ConnectX NIC)
    └─> DeserializeStage
    └─> PreprocessNLPStage (BERT tokenization)
    └─> TritonInferenceStage (sid-minibert)
    └─> MonitorStage
```

Hardware requirement: BlueField-2/3 DPU + NVIDIA GPU on same NUMA node

**DOCA Real-time VDB example** (`examples/doca/vdb_realtime/`): Streams packet data
to a vector database for RAG-based threat queries.

### Digital Fingerprinting Pipeline
**Files:** `examples/digital_fingerprinting/`
- Processes CloudTrail logs through Autoencoder
- Establishes user behavior baseline during training period
- Flags deviations with anomaly scores
- Production deployment: run continuously against management access logs

### Data Loss Prevention Pipeline
**Files:** `examples/data_loss_prevention/`
- Regex stage: fast wide-net pattern matching
- GLiNER stage: semantic validation of regex hits
- Can process network packet payloads, file contents, API responses

---

## Integration Points

### Input Sources Supported
| Source | Stage | Notes |
|---|---|---|
| DOCA (BlueField/ConnectX) | DocaSourceStage | Live packet capture; EARLY ACCESS |
| Kafka | KafkaSourceStage | OAuth supported; primary enterprise integration |
| HTTP server | HttpServerSourceStage | REST API input |
| File (CSV/JSON/Parquet) | FileSourceStage | Batch analysis |
| AWS CloudTrail | CloudTrailSourceStage | Native AWS log parsing |
| Azure | AzureSourceStage | Cloud log ingestion |
| Zeek logs | Built-in parser support | Network flow analysis |
| RSS feeds | RSSSourceStage | Threat feed ingestion |

### Output Targets Supported
| Target | Stage |
|---|---|
| Elasticsearch | WriteToElasticsearchStage |
| Kafka topic | WriteToKafkaStage |
| Vector DB (Faiss, Milvus, Kinetica) | WriteToVectorDBStage |
| File | WriteToFileStage |

### LLM/RAG Integration
- OpenAI API, NVIDIA NeMo, NVIDIA Foundation Models
- Vector database (Faiss/Milvus) for enterprise knowledge base
- Enables natural language querying of security telemetry

---

## Hardware Requirements
- NVIDIA GPU (Ampere architecture or newer recommended)
- For DOCA pipeline: BlueField-2/3 DPU + GPU on same NUMA node
- DOCA GPUNetIO configuration + hugepages
- CUDA 12.5+, Python 3.10+

## Deployment
```bash
# Production container (NVIDIA AI Enterprise)
docker pull nvcr.io/nvidia/morpheus/morpheus:25.06.00

# DOCA-specific container (Early Access)
# Request via NVIDIA Morpheus contact
${MORPHEUS_DOCA_IMAGE}

# Triton model server
docker pull nvcr.io/nvidia/morpheus/morpheus-tritonserver-models:25.10
```

## License and Repository
- Apache 2.0 (open source)
- GitHub: https://github.com/nv-morpheus/Morpheus
- Docs: https://docs.nvidia.com/morpheus/
- NGC containers: nvcr.io/nvidia/morpheus/
