# NVIDIA DOCA Vault — Data-Layer Security for Agentic AI
Source: WEKA / NVIDIA joint article
URL: https://www.weka.io/article/for-weka-and-nvidia-securing-agentic-ai-starts-at-the-data-layer

## Core Function

DOCA Vault operates as an inline authorization enforcement system running in BlueField
silicon, enforcing granular authorization on every file access request, independent
of the host and storage system.

## Three Primary Protective Capabilities

1. **Program Execution Control** — Governs which applications can run in the AI environment
2. **File Creation Prevention** — Blocks unauthorized file generation that could
   compromise data integrity
3. **Model Exfiltration Blocking** — Prevents unauthorized extraction of model weights
   and proprietary AI assets

## Architecture: Outside the Host Trust Domain

DOCA Vault operates "outside the host trust domain" — security enforcement occurs at
hardware level rather than relying on host OS protections. This means:
- Enforcement persists even if host OS is fully compromised
- Operates at line-rate speeds (800 Gb/s)
- No host CPU overhead for policy enforcement

## Integration with DOCA Ecosystem

DOCA Vault + DOCA Argus + DOCA Flow create layered protection:
- Argus: Runtime process/memory monitoring
- Vault: File/model access authorization
- Flow: Network segmentation and packet processing

When combined with WEKA NeuralMesh for persistent inference memory:
- Identity verification at access time
- Governed memory access for autonomous AI agents
- Data-path policy enforcement inline

## CTI Implications

**Critical risk point**: DOCA Vault's authorization logic for AI model access means:
- A vulnerability in DOCA Vault (or its API) directly exposes model weights
- Any bypass of Vault authorization = undetected model theft even on a "secured" system
- The DOCA collectx vulnerabilities (CVE-2025-23257/23258) show DOCA packages
  can have local privilege escalation — a foothold for Vault bypass attempts
