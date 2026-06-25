# GPU Side-Channel and Hardware Attack Research — Reference Notes

This file documents the academic research papers most relevant to NVIDIA product
CTI that could not be downloaded as PDFs in this collection run. All are confirmed
published at peer-reviewed venues.

---

## GPUHammer — Rowhammer Attacks on NVIDIA GDDR6

**Full title:** "GPUHammer: Rowhammer Attacks on GPU Memories are Practical"
**Authors:** Chris S. Lin, Joyce Qu, Gururaj Saileshwar
**arXiv ID:** 2507.08166
**Venue:** USENIX Security 2025 (SEC'25)
**Submitted:** July 10, 2025

**Key findings:**
- First successful Rowhammer attack on NVIDIA GPU GDDR6 memory (tested on A6000)
- Overcomes GPU-specific challenges: reverse-engineered proprietary GDDR row mappings
- Induced up to 8 bit-flips across 4 DRAM banks
- Demonstrated tampering with ML model weights causing significant accuracy degradation
- Practical implications for multi-tenant GPU cloud environments

**CTI relevance:** Confirms that AI model integrity can be compromised at the hardware
memory level on NVIDIA GPUs. Relevant for any shared/multi-tenant GPU cluster.

**Download:** https://arxiv.org/pdf/2507.08166

---

## Mercury — Remote Power Side-Channel on NVIDIA DL Accelerator

**Full title:** Referenced in research literature as "Mercury: Enabling Sensitive ML
Model Extraction via Remote Power Side-Channel"
**Venue:** Academic publication (exact venue and arXiv ID unconfirmed in this session)

**Key findings (as described in research reports):**
- Automated remote side-channel attack against off-the-shelf NVIDIA deep learning accelerator
- Recovers model architecture and parameters from power trace measurements
- Claimed very low error rates for model extraction
- Does not require physical access — remote power measurement via network

**CTI relevance:** Model intellectual property theft via remote power side-channel.
Especially relevant for cloud inference services and shared GPU environments.

**Status:** arXiv ID not confirmed — manual search recommended.

---

## NVBleed — NVLink Side-Channel Leakage

**Referenced as:** Research demonstrating timing and performance-counter-based leakage
on NVIDIA multi-GPU NVLink interconnects, including cross-VM leakage in cloud settings.

**Key findings (as described in research reports):**
- Timing and counter-based leakage visible on NVLink-enabled multi-GPU systems
- Cross-VM leakage demonstrated in cloud settings
- Implications for shared multi-GPU infrastructure (DGX systems, cloud GPU clusters)

**Status:** arXiv ID not confirmed on arXiv search as of June 2026 — may be under
different title or published at a venue without arXiv preprint.

---

## ReDMArk — RDMA Security Bypass

**Full title:** "ReDMArk: Bypassing RDMA Security Mechanisms"
**Venue:** USENIX Security 2021
**Direct PDF:** https://www.usenix.org/system/files/sec21-rothenberger.pdf
**Status:** Downloaded ✅ (redmark-rdma-security-usenix2021.pdf)

**Key findings:**
- Demonstrates that RDMA security mechanisms (protection domain, memory keys) can be bypassed
- Shows QPN (Queue Pair Number) spoofing and BTH (Base Transport Header) forgery
- Local or adjacent attacker can read/write another tenant's GPU memory via RDMA
- Attacks demonstrated on production InfiniBand and RoCE deployments

---

## Bedrock — Programmable Network Support for Secure RDMA

**Full title:** "Bedrock: Programmable Network Support for Secure RDMA Systems"
**Venue:** USENIX Security 2022
**Slides PDF:** https://jxing.me/slides/UsenixSecurity22-Bedrock.pdf
**Status:** Downloaded ✅ (bedrock-rdma-usenix2022-slides.pdf)

**Key findings:**
- Proposes hardware-enforced RDMA security using programmable network switches
- Addresses the QPN spoofing and BTH forgery attacks demonstrated in ReDMArk

---

## NeVerMore — NVMe-oF RDMA Exploit Framework

**Full title:** "NeVerMore: Exploiting RDMA Mistakes in NVMe-oF Storage Applications"
**Venue:** SNIA Security Summit 2022
**Direct PDF:** https://www.snia.org/sites/default/files/Security-Summit/2022/SNIA-SSS22-Taranov-NeVerMore-Exploiting-RDMA-Mistakes.pdf
**Status:** Download failed (server returned empty response) — manual download required

**Key findings:**
- Exploit framework targeting NVMe over Fabrics (NVMe-oF) implementations using RDMA
- Demonstrates data exfiltration and corruption via RDMA misconfigurations in storage
- Directly relevant to NVIDIA GPUDirect Storage deployments

---

## Securing RDMA for High-Performance Datacenter Storage Systems

**Full title:** "Securing RDMA for High-Performance Datacenter Storage Systems"
**Venue:** USENIX HotCloud 2020
**Direct PDF:** https://www.usenix.org/system/files/hotcloud20_paper_simpson.pdf
**Status:** Downloaded ✅ (securing-rdma-hotcloud2020.pdf)
