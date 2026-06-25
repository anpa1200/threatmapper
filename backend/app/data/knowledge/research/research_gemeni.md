Threat Intelligence and Product Security Assessment: NVIDIA Ecosystem and AI Infrastructure
Executive Summary
The proliferation of accelerated computing and artificial intelligence has positioned NVIDIA infrastructure at the center of the global technology landscape. This intelligence report provides an exhaustive, evidence-based assessment of the cyber threat environment surrounding NVIDIA’s ecosystem, with a specialized focus on NVIDIA Networking, AI data center architecture, and supply chain security. The analysis evaluates confirmed vulnerabilities, architectural attack surfaces, and the capabilities of advanced persistent threats (APTs) targeting the semiconductor and high-performance computing (HPC) sectors.
The following findings represent the core analytic assessments derived from current intelligence and product-security disclosures:
Direct Extortion and IP Theft (High Confidence): NVIDIA has been the direct victim of high-impact extortion operations, most notably by the LAPSUS$ threat group in 2022. The intrusion resulted in the exfiltration of approximately 1TB of proprietary data, including hardware schematics, GPU driver source code, and code-signing certificates. These certificates were subsequently weaponized by disparate threat actors to sign third-party malware, allowing malicious payloads to bypass Windows driver signature enforcement1.
Critical Container Escape Risks in AI Clusters (High Confidence): The AI infrastructure stack exhibits critical vulnerabilities at the container isolation boundary. CVE-2025-23266 (CVSS 9.0), designated "NVIDIAScape," is a critical flaw within the NVIDIA Container Toolkit. Exploitation of Open Container Initiative (OCI) hooks via LD_PRELOAD manipulation enables an attacker to escape container boundaries and achieve arbitrary code execution with root privileges on the underlying host, fundamentally threatening multi-tenant GPU environments5.
Command Injection in Network Operating Systems (High Confidence): Core networking infrastructure, specifically devices running Cumulus Linux and NVOS, presents a highly exploitable attack surface within the NVIDIA User Experience (NVUE) management interface. Recent disclosures, including CVE-2025-33179 (CVSS 8.8) and CVE-2025-33181 (CVSS 7.3), demonstrate that low-privileged or adjacent attackers can execute unauthorized commands and escalate privileges, leading to complete switch compromise9.
DPU Control Plane Vulnerabilities (High Confidence): The BlueField Data Processing Unit (DPU) and its accompanying DOCA software framework act as the hardware root of trust for modern AI factories. However, vulnerabilities such as CVE-2025-23256 (CVSS 8.7) in the management interface, alongside privilege escalation flaws in DOCA collectx packages (CVE-2025-23257, CVE-2025-23258), highlight the emerging risk of adversaries bypassing host OS security by compromising the isolated infrastructure processor11.
State-Sponsored Targeting of the AI Supply Chain (Medium Confidence): Chinese-nexus APT groups are responsible for an estimated 58% of state-sponsored cyberattacks against the global technology sector. These operations systematically target AI training datasets, machine-learning infrastructure, and proprietary semiconductor intellectual property to evade export controls and accelerate domestic capabilities16.
Edge Infrastructure Exploitation by Nation-States (High Confidence): Advanced threat groups, prominently the PRC-aligned Volt Typhoon, actively compromise network edge devices (routers, switches, firewalls) using "living off the land" (LOTL) techniques to build covert proxy networks (e.g., KV Botnet) and exfiltrate configurations. While direct targeting of NVIDIA Spectrum switches by Volt Typhoon is unconfirmed, this class of enterprise networking hardware perfectly aligns with their established operational methodology18.
Geopolitical Risk Concentrated in Israel (High Confidence): NVIDIA’s networking division is heavily anchored by its Yokneam-based R&D centers, established following the $6.9 billion acquisition of Mellanox Technologies. This geographic concentration exposes NVIDIA infrastructure to Iranian threat clusters such as UNC3890, which actively targets Israeli technology, government, and shipping sectors using custom implants like SUGARUSH and SUGARDUMP21.
Inherent Protocol Weaknesses in RDMA/RoCE (Medium Confidence): Remote Direct Memory Access (RDMA) over Converged Ethernet (RoCE) is foundational to high-speed GPUDirect communications. However, base RDMA protocols lack robust authentication and encryption. Academic frameworks such as "ReDMArk" have demonstrated that local or adjacent attackers can spoof Queue Pair Numbers (QPN) to achieve unauthorized memory access or denial-of-service across the fabric25.
Insecure Defaults in Edge AI Deployments (High Confidence): Embedded edge and automotive AI platforms, including Jetson and DRIVE, face physical and adjacent network threats. Vulnerabilities like CVE-2026-24148 (CVSS 9.4) expose systemic flaws in initialization logic, where insecure default configurations allow unprivileged attackers to disclose encrypted data and disrupt services across devices sharing identical machine IDs28.
The Shift Toward In-Silicon Security (Analytic Assessment): The introduction of DOCA Argus for memory introspection and DOCA Vault for file access control shifts the defensive perimeter from the host OS directly into the BlueField silicon. While this architecture effectively mitigates traditional host-level rootkits, it centralizes trust, meaning DPU firmware and DOCA API security must become the highest priority for product-security engineering30.
NVIDIA Technology Map
Understanding the NVIDIA ecosystem requires delineating the complex interplay between hardware acceleration, specialized networking, and software frameworks. The following table maps the primary security-relevant technologies and their associated attack surfaces.
Product / Technology
Category
Purpose
Security Relevance
Main Attack Surfaces
Key References
BlueField DPU
Networking / Compute
Infrastructure accelerator offloading networking, storage, and security from host CPUs.
Serves as the hardware root of trust and isolation boundary for AI factories.
Management interfaces (BMC), firmware, PCIe boundary, DOCA services.
[cite: 30, 33, 34]
DOCA
Software / SDK
Software framework for developing DPU/SuperNIC-accelerated services.
Enforces security policies (Argus, Vault). Vulnerabilities here compromise the DPU trust domain.
APIs, RPC endpoints, SDK libraries, collectx telemetry packages.
[cite: 12, 13, 34]
Cumulus Linux / NVOS
Switch OS
Network operating system for Spectrum Ethernet switches.
Core fabric routing. Compromise allows traffic interception, DoS, and lateral movement.
NVUE management interface, SSH, BGP/OSPF daemons, SNMP.
[cite: 9]
Spectrum-X / Switches
Hardware
High-performance Ethernet and InfiniBand switching for AI clusters.
Carries all East-West GPU training traffic and North-South management traffic.
Switch management plane, ipfilter configurations, firmware updates.
[cite: 35, 36]
ConnectX / SuperNIC
Hardware
High-speed Ethernet/InfiniBand network interface cards.
Handles RDMA/RoCE data streams at up to 800 Gb/s.
Firmware, host drivers, VPI software, PCIe interconnect.
[cite: 33, 37]
Pure SONiC
Switch OS
Open-source Linux network OS for switches supported by NVIDIA.
Alternative to Cumulus Linux; governs switch control plane behavior.
BGP daemons, Switch State Service (SwSS), Redis database, management plane.
[cite: 33]
NVIDIA Container Toolkit
Software
Enables containers to leverage underlying NVIDIA GPUs.
Bridges container isolation and host GPU resources. Critical security boundary.
OCI hooks, libnvidia-container, environment variable parsing (LD_PRELOAD).
[cite: 5, 6, 7]
GPUDirect (RDMA/Storage)
Technology
Bypasses host CPU to transfer data directly between NIC/Storage and GPU memory.
Maximizes performance but bypasses traditional host-based OS security monitoring.
RDMA packet injection, lack of encryption/auth in legacy deployments.
[cite: 38, 39]
Jetson / DRIVE
Edge / Auto AI
Edge computing and autonomous vehicle platforms.
High physical accessibility; deployed in hostile/remote environments.
Initialization logic, bootloader, L4T kernel, device identity.
[cite: 28, 29]
AIStore / AI Enterprise
Software
Scalable AI storage and deployment frameworks.
Manages access to training datasets and model weights.
Authentication APIs, Kubernetes RBAC, Web UIs.
[cite: 40, 41, 42]
Omniverse
Software
Platform for developing Universal Scene Description (OpenUSD) applications.
Manages sensitive 3D datasets, digital twins, and industrial simulations.
Authentication flows, Launcher log files, network proxy configurations.
[cite: 43, 44, 45]

The convergence of these technologies creates a paradigm where traditional security perimeters are inadequate. Accelerated computing relies on bypassing the central processing unit (CPU) to eliminate latency, which inadvertently bypasses decades of host-based security tooling designed to monitor CPU memory and system calls.
NVIDIA Networking Deep Dive
NVIDIA's transformation into a comprehensive AI infrastructure provider was solidified by the acquisition of Mellanox Technologies. The integration of high-performance networking is essential because modern AI models cannot be trained on a single GPU; they require thousands of synchronized processors operating as a single unified engine.
BlueField DPU and DOCA
The BlueField Data Processing Unit (DPU) is an advanced infrastructure computing platform that powers the Agentic AI factory. By combining ARM CPU cores, programmable network adapters, and hardware accelerators, BlueField isolates infrastructure services (like routing, firewalling, and storage encryption) from the primary host workload domain34. DOCA is the unified software framework enabling developers to rapidly program these DPUs.
Adversaries are increasingly focused on the DPU because it holds the keys to the kingdom. If a threat actor compromises the BlueField DPU or the DOCA runtime environment, they effectively operate below the visibility of the host operating system. NVIDIA has responded by pushing security deeper into the silicon. The DOCA Argus microservice performs real-time runtime threat detection via zero-copy memory analysis, inspecting host memory without relying on vulnerable software agents30. Similarly, DOCA Vault enforces granular, file-based access controls for AI storage directly in the data path, ensuring that only authorized AI agents can access model weights and training datasets, even if the host OS is completely compromised30. However, this centralization of security controls means that vulnerabilities within DOCA itself—such as the recent privilege escalation flaws in collectx telemetry packages (CVE-2025-23257, CVE-2025-23258)—pose a catastrophic risk to the entire zero-trust architecture12.
Spectrum-X Ethernet, Quantum InfiniBand, and Switch Operating Systems
The East-West traffic of AI training (GPU-to-GPU communication) is facilitated by Quantum InfiniBand and Spectrum-X Ethernet switches33. To manage this fabric, administrators rely on network operating systems such as Cumulus Linux, NVOS, and the open-source Pure SONiC.
From an adversary's perspective, network switches are prime targets because they lack standard Endpoint Detection and Response (EDR) agents, are rarely updated, and process all lateral traffic within the data center. The management plane—specifically the NVIDIA User Experience (NVUE) interface—is a critical security boundary. Vulnerabilities such as CVE-2025-33179 and CVE-2025-33181 have demonstrated that improper sanitization of user input in NVUE can lead to command injection, allowing low-privileged actors to execute arbitrary shell commands and seize control of the switch9. A compromised Spectrum switch could enable an attacker to manipulate Border Gateway Protocol (BGP) routes, passively intercept unencrypted RDMA traffic, or launch distributed denial-of-service (DoS) attacks against the cluster, as seen in the ipfilter exhaustion flaw (CVE-2024-0101)35.
RoCE, RDMA, and GPUDirect
Remote Direct Memory Access (RDMA) and RDMA over Converged Ethernet (RoCE) allow network adapters to read and write directly to application memory, bypassing the CPU and OS kernel. NVIDIA's GPUDirect Storage and GPUDirect RDMA extend this capability, allowing NVMe storage arrays and remote network interfaces to push data directly into GPU memory (VRAM)38.
While crucial for maximizing throughput and minimizing latency, this architectural bypass creates systemic security challenges. Original RDMA protocols were designed for highly trusted, physically isolated HPC environments and lack native packet encryption or strong endpoint authentication25. Security researchers have demonstrated framework attacks, such as "ReDMArk," which exploit the predictability of Queue Pair Numbers (QPN) and Base Transport Headers (BTH) to forge RDMA packets. A local or adjacent attacker could theoretically spoof RDMA packets to read sensitive data from another tenant's GPU memory, or overwrite active model weights during a training run26. Securing this fabric requires strict network isolation, the deployment of IPsec over RoCEv2 where supported, and the integration of hardware-enforced partitioning (such as Multi-Instance GPU configurations) to prevent cross-tenant data leakage.
Public Vulnerability and Advisory Review
The following table synthesizes confirmed public vulnerabilities across the NVIDIA ecosystem, filtered strictly for verifiable PSIRT advisories, National Vulnerability Database (NVD) records, and high-impact Common Vulnerabilities and Exposures (CVEs).

CVE / Advisory ID
Product / Component
Affected Versions
Vulnerability Class
Severity / CVSS
Exploitation Status
Patch / Mitigation
Source URL
Confidence
CVE-2025-23266
NVIDIA Container Toolkit & GPU Operator
Toolkit < 1.17.7, Operator < 25.3.0
Container Escape / Arbitrary Code Execution
9.0 (Critical)
PoC Available / Unknown in Wild
Upgrade to 1.17.8; Disable enable-cuda-compat hook
NVD / Sec 5659
[cite: 5, 6, 51]
High
CVE-2026-24148
Jetson for JetPack
< 35.6.4
Insecure Default Initialization
9.4 (Critical)
Unknown
Upgrade to 35.6.4; Ensure unique machine IDs
NVD / Sec 5797
[cite: 28, 29]
High
CVE-2025-33181
Cumulus Linux & NVOS
< 5.14, < 5.11.4
Command Injection (NVUE Interface)
7.3 (High)
Unknown
Apply NVOS patches; Restrict NVUE access
NVD / Sec 5722
[cite: 9, 52]
High
CVE-2025-33179
Cumulus Linux & NVOS
< 5.14, < 5.11.4
Privilege Escalation (NVUE Interface)
8.8 (High)
Unknown
Apply NVOS patches; Restrict NVUE access
NVD / Sec 5722
[cite: 10]
High
CVE-2025-23256
BlueField DPU Firmware
GA < 45.1020, LTS < 35.4554
Incorrect Authorization (Management Interface)
8.7 (High)
Unknown
Apply DPU Firmware Updates
NVD / Sec 5655
[cite: 11]
High
CVE-2025-23258
DOCA (collectx-dpeserver)
< 2.5.4, < 2.9.3
Privilege Escalation (Incorrect Permissions)
7.3 (High)
Unknown
Update DOCA Host software package
NVD / Sec 5655
[cite: 14, 15]
High
CVE-2024-0101
Mellanox OS, ONYX, Skyway
< 3.11.2002
Protection Mechanism Failure (ipfilter DoS)
7.5 (High)
Unknown
Update Switch OS; ACL filtering on Mgmt Plane
NVD / Sec 5559
[cite: 35, 36]
High
CVE-2026-24187
Linux GPU Display Driver
< 596.36
Use-After-Free
8.8 (High)
Unknown
Update GPU Drivers
NVD / Sec 5821
[cite: 53, 54]
High
CVE-2025-23289
Omniverse Launcher
< 1.9.19
Information Disclosure (Proxy Logs)
5.5 (Medium)
Unknown
Update Launcher Client
NVD / Sec 5679
[cite: 44, 45]
High
CVE-2022-28181
vGPU / Linux Display Driver
Multiple
Out-of-Bounds Write (RCE via Shaders)
8.5 (High)
Unknown
Patch vGPU software; Restrict GPU API access
NVD / Sec 5353
[cite: 55]
High
CVE-2025-33185
AIStore
Multiple
Missing Authorization (AuthN API)
6.9 (Medium)
Unknown
Update AIStore API libraries
Snyk
[cite: 41]
High

An analysis of this vulnerability data reveals distinct patterns in the attack surface. High-severity flaws are predominantly found in management interfaces (NVUE, BMC), container bridging software (OCI hooks), and kernel-level graphics drivers. The transition toward hardware-level offloading has simultaneously shifted vulnerabilities into the firmware and management planes of DPUs and switches, which often lack automated patching mechanisms compared to standard host operating systems.
Attack Surface Analysis
The NVIDIA ecosystem introduces highly specialized components that expand the traditional enterprise attack surface. The following sections delineate the mechanical risks associated with these environments.
Management Interfaces
Network management planes represent the most accessible target for initial access and privilege escalation. Interfaces such as NVUE on Cumulus Linux, the Baseboard Management Controller (BMC) on BlueField DPUs, and out-of-band management ports on Spectrum switches are frequently exposed to adjacent corporate networks. Flaws like CVE-2025-33179 highlight how incomplete input validation in NVUE allows low-privileged users to inject arbitrary shell commands9. Similarly, authorization bypasses in the BlueField management interface (CVE-2025-23256) could permit an attacker to alter the configuration of the DPU, dismantling the hardware root of trust protecting the host server11.
Firmware and Update Chain
Firmware updates for highly specialized hardware (SuperNICs, ConnectX, Spectrum switches) are often applied manually or via unmonitored scripts. Threat actors recognize that manipulating firmware provides deep, persistent access that survives operating system reinstallations. Extortion campaigns by groups like LAPSUS$ resulted in the theft of NVIDIA's proprietary code-signing certificates. Cybercriminal elements immediately weaponized these expired but historically trusted certificates to sign malicious Windows drivers, embedding remote access trojans (RATs) such as Quasar and Cobalt Strike deep within the OS kernel, bypassing standard defense-in-depth measures like Secure Boot and Endpoint Detection and Response (EDR)3.
Drivers and Kernel Modules
The proprietary NVIDIA display and compute drivers (nvidia.ko on Linux, nvlddmkm.sys on Windows) are complex codebases executing in Ring 0 (kernel mode). They must parse untrusted input from user-space applications (such as shader code or API requests). Vulnerabilities in these drivers frequently manifest as memory corruption issues—Out-of-Bounds writes (CVE-2022-28181), Use-After-Free conditions (CVE-2026-24187), and Integer Overflows (CVE-2023-25516)54. In multi-tenant cloud environments offering virtualized GPUs (vGPU), these driver flaws enable attackers to break out of guest virtual machines, potentially compromising the underlying hypervisor and exposing sibling tenants.
DPU Control Plane
The BlueField DPU is marketed as a zero-trust enclave, running DOCA microservices to govern networking, storage, and security. However, this software stack is an emerging attack surface. Components like the DOCA collectx telemetry daemon must execute with elevated privileges to gather hardware metrics. Incorrect permission assignments within these Debian packages (CVE-2025-23257, CVE-2025-23258) grant local attackers the ability to escalate to root privileges on the ARM processors of the DPU12. A compromised DPU grants an adversary complete visibility into network flows and the ability to silently manipulate data before it ever reaches the host CPU.
Switch OS
Whether utilizing Cumulus Linux, NVOS, or Pure SONiC, network operating systems are susceptible to both control plane and data plane attacks. Denial of service vulnerabilities, such as the ipfilter exhaustion flaw in Mellanox OS/ONYX (CVE-2024-0101), allow attackers to crash the switch by sending crafted, unauthenticated packets35. A compromised switch allows for sophisticated man-in-the-middle (MitM) attacks against AI workloads, capturing proprietary training data traversing the Ethernet or InfiniBand fabric.
SDKs, Libraries, and Package Dependencies
Software Development Kits like DOCA and AI frameworks like NeMo and Triton rely heavily on third-party dependencies, Python libraries, and pre-compiled binaries. Supply chain risks are amplified in AI environments where data scientists frequently pull models and dependencies from open-source repositories. To mitigate this, NVIDIA leverages Software Bill of Materials (SBOM) and SLSA Build Provenance attestations for critical toolkits (e.g., the AI Cluster Runtime, NVSentinel)59. However, deserialization vulnerabilities across the AI software stack remain prevalent, exposing hosts to remote code execution if malicious model files or configuration manifests are ingested.
CI/CD and Build Systems
Continuous Integration and Continuous Deployment (CI/CD) pipelines represent the most effective vector for adversaries seeking to insert backdoors into AI infrastructure at scale. The theft of proprietary source code and development tools (as observed in the LAPSUS$ incident) allows attackers to study internal mechanisms for zero-day discovery, or theoretically implant malicious code upstream before it is packaged into Docker images or firmware blobs2.
AI Cluster Networking and RDMA
The use of GPUDirect RDMA minimizes latency by allowing direct GPU-to-GPU data transfers across the network. Because this traffic bypasses the host operating system's networking stack, it is invisible to traditional host-based firewalls and IDS/IPS systems38. Unencrypted RoCEv2 or InfiniBand traffic is vulnerable to interception and injection. Furthermore, misconfigurations in MAC VLANs or Priority Flow Control (PFC) mechanisms required for lossless Ethernet can be abused by attackers to trigger network-wide denial-of-service storms39.
Cloud/HPC Deployment Exposure and Misconfiguration Risk
Customer misconfiguration is a persistent vulnerability multiplier. In cloud AI factories, failure to properly segment management networks, restrict API access, or implement strict Kubernetes Role-Based Access Control (RBAC) often results in exposure. For instance, misconfigured and unauthenticated NVIDIA Riva endpoints (used for speech AI) have been actively discovered exposed to the public internet, allowing attackers to abuse expensive GPU compute resources or extract proprietary voice models63.
Relevant Threat Actors and APT Groups
The targeting of the semiconductor and AI infrastructure sectors is heavily dominated by sophisticated, state-sponsored entities seeking intellectual property, alongside financially motivated cybercriminal syndicates.
Actor / Group
Source
Sector Relevance
Direct NVIDIA Relevance
Known Targeting
Relevant TTPs
Evidence Links
Confidence
LAPSUS$
Extortion
High
Direct
Semiconductor, Tech, Telecom
Insider bribery, extortion, code-signing cert theft, driver source code theft, public leaks via Telegram.
[cite: 1, 2, 4, 61]
High
Volt Typhoon
State-Sponsored (PRC)
High
Indirect (Edge/Switch Infra)
Critical Infra, Telecom, Networking
"Living off the Land" (LOTL), router/switch compromise, proxy botnets (KV Botnet), config exfiltration.
[cite: 18, 19, 20, 64]
High
UNC3890
State-Sponsored (Iran)
High
Sector-Level (Israel, Tech)
Israel Shipping, Gov, Energy, Tech
Watering holes, credential harvesting, custom backdoors (SUGARUSH), credential stealers (SUGARDUMP).
[cite: 23, 24, 65, 66]
High
APT41 / APT40
State-Sponsored (PRC)
High
Sector-Level (Semiconductor, AI)
High-Tech, R&D, Manufacturing
Supply chain compromise, IP theft, custom rootkits/bootkits, prolonged stealthy persistence.
[cite: 67, 68]
High
Flax Typhoon
State-Sponsored (PRC)
Medium
Indirect (Edge Infra)
Telecom, Critical Infra
Large-scale botnets targeting network edge routers and IoT devices to obscure C2 traffic.
[cite: 69]
High

Analytic assessment of these threat actors reveals distinct motivations. State-sponsored groups from the People's Republic of China (PRC) focus intensely on overcoming geopolitical export restrictions by stealing proprietary semiconductor manufacturing techniques, AI models, and algorithmic research. Conversely, Iranian threat actors prioritize disruption, regional espionage, and targeting Israeli-based entities, posing a unique geographic risk to NVIDIA's operations in the Middle East.
Direct vs Indirect Evidence
To maintain analytic rigor, evidence of threat actor activity must be clearly delineated between direct operations against NVIDIA and indirect operations targeting adjacent technologies or sectors.
Direct Evidence Related to NVIDIA
There is unassailable, direct evidence that threat actors target NVIDIA as a corporate entity and exploit its technology stack.
The LAPSUS$ Breach (2022): This extortion group breached NVIDIA's corporate network, exfiltrating 1TB of highly sensitive data. The attackers specifically targeted the core of NVIDIA's IP, demanding the company open-source its GPU drivers and remove the Lite Hash Rate (LHR) cryptocurrency mining limiters from the RTX 30-series GPUs. When demands were refused, the group leaked 71,000 employee credential hashes, proprietary schematics, and highly sensitive code-signing certificates1.
Weaponization of Stolen Certificates: Following the LAPSUS$ leak, the broader cybercriminal ecosystem immediately adopted the stolen NVIDIA code-signing certificates to sign remote access trojans (RATs) such as Quasar, Mimikatz, and Cobalt Strike beacons. Because the certificates were historically trusted, this allowed malware to bypass Windows Defender Application Control and driver signature enforcement3.
NVIDIA Product Exploitation: The regular discovery and patching of critical vulnerabilities within NVIDIA products—such as the NVIDIAScape container escape (CVE-2025-23266)6 and the NVUE command injection flaws (CVE-2025-33179)10—constitutes direct evidence of highly exploitable attack surfaces within the core product ecosystem, actively researched by security teams and potentially targeted by adversaries.
Indirect but Relevant Evidence (Sector/Adjacent Targeting)
There is substantial intelligence indicating that the infrastructure architectures utilized by NVIDIA are actively targeted by sophisticated adversaries, even if direct attribution to an NVIDIA product compromise is not publicly confirmed.
Targeting the Semiconductor and AI Supply Chain: Chinese-nexus APT groups account for an estimated 58% of state-sponsored cyberattacks against the global technology sector. These operations systematically target AI training datasets, machine-learning infrastructure, and proprietary IP. This represents a sustained strategic campaign to achieve parity in AI capabilities amidst international sanctions16.
Edge Device and Router Exploitation (Volt Typhoon): The PRC-aligned group Volt Typhoon demonstrates a highly refined operational methodology focused on compromising enterprise network edge devices (routers, switches, and firewalls) that have reached end-of-life or lack updates. They utilize these compromised hardware platforms to build covert proxy networks (e.g., the KV Botnet) and execute "living off the land" techniques to extract routing configurations and credentials without deploying traditional malware18. While public reports predominantly cite Cisco, Fortinet, and Netgear, NVIDIA's Spectrum switches and Cumulus Linux environments are functionally identical targets within enterprise data centers.
Geopolitical Threat to Israeli Operations (UNC3890): Following the acquisition of Mellanox, NVIDIA's networking division became deeply rooted in Yokneam, Israel. NVIDIA is rapidly expanding its footprint with a planned 160,000-square-meter campus in Kiryat Tivon and the Israel-1 supercomputer21. This geographic presence inherently exposes the company to regional threats. Iranian APT clusters, specifically UNC3890, systematically target Israeli technology, energy, and shipping organizations. They utilize localized watering hole attacks, credential harvesting, and custom implants (SUGARUSH, SUGARDUMP) to establish persistence and exfiltrate data23. The strategic value of NVIDIA's networking IP makes these facilities a high-value target for state-sponsored espionage.
MITRE ATT&CK Mapping
The following table maps relevant adversary behaviors and theoretical attack paths against the NVIDIA ecosystem to the MITRE ATT&CK framework.

Tactic
Technique ID
Technique Name
Why Relevant
Supporting Evidence
Confidence
Initial Access
T1190
Exploit Public-Facing Application
Edge devices, switches, and AI frameworks exposed to networks are prime targets for initial compromise.
CVE-2025-33181 (NVUE Command Injection), CVE-2024-0101 (Mellanox ipfilter DoS).
High9
Execution
T1059.004
Command and Scripting Interpreter: Unix Shell
Exploitation of management interfaces often yields direct shell access to the underlying Linux OS.
Command injection vulnerabilities in Cumulus Linux/NVOS.
High9
Privilege Escalation
T1611
Escape to Host
Attackers escaping AI container workloads to access host GPU resources, memory, and parallel tenant data.
CVE-2025-23266 (NVIDIAScape Container Toolkit OCI hook exploit).
High6
Privilege Escalation
T1574.006
Hijack Execution Flow: LD_PRELOAD
Environmental variable manipulation to force the dynamic linker to load malicious shared libraries (.so).
Primary exploitation mechanism utilized in the NVIDIAScape container escape.
High6
Defense Evasion
T1553.002
Subvert Trust Controls: Code Signing
Adversaries use stolen certificates to sign malware, making it appear as legitimate hardware drivers.
LAPSUS$ leak of NVIDIA certificates subsequently used to sign RATs (Cobalt Strike, Quasar).
High3
Defense Evasion
T1014
Rootkit
Establishing deep persistence in kernel memory or DPU firmware to hide from host-based EDR.
Use of malicious GPU drivers or theoretical BlueField DPU compromises to evade detection.
Medium68
Credential Access
T1003
OS Credential Dumping
Harvesting administrative credentials from network infrastructure to facilitate lateral movement.
LAPSUS$ leak of 71,000 employee hashes; Volt Typhoon extracting domain hashes from network edge devices.
High2
Lateral Movement
T1210
Exploitation of Remote Services
Moving through the data center fabric by exploiting trusted internal protocols.
Analytic Assessment: Abuse of RDMA/RoCE protocols (ReDMArk framework) to alter remote memory without OS detection.
Low26
Exfiltration
T1567
Exfiltration Over Web Service
Stealing large volumes of proprietary data (source code, AI models) via cloud services to blend in.
LAPSUS$ exfiltrating 1TB of NVIDIA data; APT41 using cloud platforms for espionage exfiltration.
High1

CTI Requirements / Priority Intelligence Requirements (PIRs)
To proactively defend the NVIDIA ecosystem and guide the Product Security Incident Response Team (PSIRT), the following Priority Intelligence Requirements (PIRs) must drive ongoing collection and hunting operations:
PIR 1: Are threat actors actively developing, discussing, or trading exploits for NVIDIA DPU or Switch OS platforms (Cumulus Linux, NVOS, DOCA)?
Collection Sources: Deep/Dark web exploit forums, GitHub vulnerability repositories, cybercriminal Telegram channels (e.g., initial access broker marketplaces).
Indicators to Monitor: Chatter mentioning specific CVEs (e.g., CVE-2025-33181, CVE-2025-23256), keywords like "NVUE", "Mellanox ipfilter", or "DOCA collectx".
Decision Supported: Prioritizing out-of-band PSIRT patching, generating emergency customer communications, and directing internal red team assessments.
Reporting Cadence: Continuous / Real-time alerting.
Confidence Criteria: Corroborated Proof-of-Concept (PoC) code or credible claims by known initial access brokers of successful network intrusions involving NVIDIA hardware.
PIR 2: Are state-sponsored groups (e.g., Volt Typhoon, Flax Typhoon) expanding their edge-device targeting methodology to include NVIDIA Spectrum switches?
Collection Sources: CISA/FBI joint cybersecurity advisories, telemetry from major incident response vendors (Mandiant, CrowdStrike, SentinelOne), and customer incident reports.
Indicators to Monitor: Unexplained modifications to switch ipfilter rules, rogue SSH sessions originating from unusual IP spaces on Cumulus Linux, anomalous BGP routing changes, or unexpected SNMP enumeration18.
Decision Supported: Hardening default switch configurations in factory releases and accelerating the publication of zero-trust network deployment guidelines for AI factories.
Reporting Cadence: Weekly review of threat landscape reports.
Confidence Criteria: Verified incident response telemetry confirming APT TTPs (e.g., KV Botnet staging) on a Spectrum switch or Mellanox device.
PIR 3: Is there evidence of "In-the-Wild" exploitation of the NVIDIA Container Toolkit vulnerability (CVE-2025-23266 / NVIDIAScape)?
Collection Sources: Cloud service provider telemetry (AWS, Azure, GCP), managed Kubernetes service logs, and high-interaction honeypots simulating vulnerable GPU clusters.
Indicators to Monitor: Anomalous LD_PRELOAD environment variable injections within containers demanding GPU access, or unexpected execution flows originating from the nvidia-ctk or enable-cuda-compat hooks6.
Decision Supported: Escalating the urgency of forced deprecation or automatic updates across managed AI cloud services (e.g., NVIDIA AI Enterprise) and issuing critical public warnings.
Reporting Cadence: Continuous / Real-time alerting.
Confidence Criteria: Telemetry demonstrating a successful host escape originating from an untrusted or third-party container image.
PIR 4: Are semiconductor or AI-focused APT groups (e.g., APT41) demonstrating targeted interest in proprietary GPU microarchitecture, DPU designs, or AI model weights?
Collection Sources: Counter-intelligence reports, academic espionage tracking, supply chain monitoring, and insider threat telemetry.
Indicators to Monitor: Spear-phishing campaigns targeting NVIDIA hardware engineers, unauthorized access attempts to internal Git repositories, or anomalous large-scale data transfers from R&D network segments67.
Decision Supported: Strengthening internal zero-trust access controls, enhancing endpoint monitoring for developers, and revising IP protection protocols.
Reporting Cadence: Monthly strategic review.
Confidence Criteria: Identification of custom malware implants (e.g., rootkits) on R&D endpoints or confirmed credential theft from engineering personnel.
PIR 5: Are supply-chain components utilized by NVIDIA products (e.g., Open-source AI libraries, Debian packages in DOCA) affected by newly disclosed software supply chain compromises?
Collection Sources: OpenSSF, NVD, Snyk vulnerability databases, and internal SBOM scanning tools.
Indicators to Monitor: Disclosures of malicious code insertion in popular Python AI libraries (e.g., PyTorch dependencies), or vulnerabilities in upstream Linux kernel modules used by Cumulus Linux.
Decision Supported: Triggering immediate internal code audits, updating SLSA Build Provenance records, and halting compromised CI/CD deployment pipelines.
Reporting Cadence: Daily automated scanning.
Confidence Criteria: Verified malicious commits in upstream repositories directly imported by NVIDIA software stacks.
Hunting and Detection Opportunities
Proactive threat hunting is essential for identifying adversaries who have bypassed preventative controls. The following hypotheses provide actionable logic for detecting sophisticated compromises within NVIDIA environments.
Hypothesis 1: Container Escape via NVIDIA Container Toolkit (CVE-2025-23266)
Required Telemetry: EDR, eBPF telemetry (e.g., Falco, Upwind, CrowdStrike), container runtime logs.
Detection Logic Concept: Flag any container initialization process where the LD_PRELOAD environment variable is passed targeting the nvidia-container-toolkit or enable-cuda-compat hook. Specifically, alert if the variable points to unexpected shared object (.so) files residing within ephemeral directories like /tmp, /dev/shm, or /proc/self/cwd/6.
Relevant ATT&CK Techniques: T1611 (Escape to Host), T1574.006 (Hijack Execution Flow: LD_PRELOAD).
Related Products: NVIDIA Container Toolkit, GPU Operator.
False Positives: Legitimate debugging, tracing, or profiling tools that leverage LD_PRELOAD to hook function calls. However, this is highly unusual during the container instantiation hook phase in production environments.
Severity: Critical.
Confidence: High.
Hypothesis 2: Malicious NVUE Command Injection (Cumulus Linux / NVOS)
Required Telemetry: Auditd logs on the switch, NVUE application logs, centralized syslog.
Detection Logic Concept: Search for shell metacharacters (e.g., ;, |, &&, ||, `) embedded within the payload bodies of API requests directed at the NVUE REST or CLI interfaces9. Correlate these requests with unexpected child processes spawning from the NVUE daemon (e.g., wget, curl, bash -c).
Relevant ATT&CK Techniques: T1059.004 (Unix Shell), T1190 (Exploit Public-Facing Application).
Related Products: Cumulus Linux, NVOS.
False Positives: Poorly formatted legitimate administrative automation scripts. However, the presence of command separators in specific parameter fields usually indicates a definitive injection attempt.
Severity: High.
Confidence: High.
Hypothesis 3: Covert Persistence via DPU Manipulation (BlueField)
Required Telemetry: DOCA Argus telemetry, host BMC authentication logs, network flow logs from the Out-of-Band (OOB) management network.
Detection Logic Concept: Establish a strict baseline for authorized administrative access to the BlueField BMC and DOCA collectx services. Alert immediately on repeated failed authentication attempts, unexpected privilege escalation commands (e.g., sudo usage by non-standard accounts), or unauthorized SSH sessions establishing connections to the ARM cores of the DPU from non-management IP subnets12.
Relevant ATT&CK Techniques: T1014 (Rootkit), T1078 (Credential Dumping), T1543 (Create or Modify System Process).
Related Products: BlueField DPUs, DOCA Framework.
False Positives: Automated provisioning or orchestration tools (e.g., Ansible, Terraform) pushing legitimate configuration updates.
Severity: Critical.
Confidence: Medium (Requires rigorous baselining to minimize noise).
PSIRT and Engineering Relevance
The intelligence derived from this report directly supports the operational priorities of the NVIDIA Product Security Incident Response Team (PSIRT) and broader engineering initiatives:
Vulnerability Prioritization: Critical flaws that breach isolation boundaries in multi-tenant cloud environments—such as the Container Toolkit escape (CVE-2025-23266) and the BlueField management interface authorization failure (CVE-2025-23256)—must be prioritized above all other patching efforts7. These vulnerabilities undermine the foundational security promises of AI cloud providers.
Enforcing Secure Defaults: The disclosure of CVE-2026-24148 regarding insecure default initialization in Jetson devices highlights a critical engineering imperative29. Edge AI devices, which are often physically accessible, must ship with hardened configurations that require user-generated credentials and unique machine IDs upon first boot, eliminating "default password" attack vectors.
Securing the New Silicon Perimeter: As NVIDIA transitions core security functions into the silicon via DOCA Argus and DOCA Vault30, engineering teams must subject these APIs to rigorous, continuous penetration testing. Because these services now constitute the primary trust boundary, any vulnerability within DOCA provides adversaries with unparalleled, invisible access.
Enhancing Exploitability Assessments: NVIDIA's practice of providing Vulnerability Exploitability eXchange (VEX) documentation is vital42. PSIRT must continue to expand this program to reduce alert fatigue for customers, particularly in complex containerized environments where security scanners frequently flag inert, unexploitable open-source dependencies.
Intelligence Gaps
Despite comprehensive analysis, several critical intelligence gaps remain regarding the threat landscape facing NVIDIA:
Exploitation in the Wild: While high-severity vulnerabilities exist for critical infrastructure like Cumulus Linux (CVE-2025-33181) and BlueField DPUs (CVE-2025-23256), there is currently no public, verifiable telemetry confirming that APTs or cybercriminal groups are actively exploiting these specific CVEs in the wild.
Weaponization of RDMA Fabrics: Academic research (e.g., ReDMArk) provides strong theoretical proof that RoCE and InfiniBand fabrics are vulnerable to packet injection and unauthorized memory access26. However, CTI lacks empirical evidence confirming that advanced threat actors (such as Volt Typhoon or UNC3890) have successfully weaponized these hardware-level protocols during actual data center intrusions.
Downstream Supply Chain Impact: The precise scope of the damage caused by the LAPSUS$ theft of NVIDIA code-signing certificates remains difficult to quantify56. While it is known that various malware families utilized these certificates, the total number of legacy Windows systems globally compromised by these forged drivers is unknown.
Adversary Presence in DPU Firmware: As security controls shift to the DPU, the capability of APTs to develop custom firmware rootkits targeting the ARM cores of SmartNICs and DPUs represents a significant unknown. The detection engineering community currently lacks mature, standardized tooling for hunting threats embedded at the PCIe or NIC firmware level.
Final Assessment
Top 10 Most Important Risks:
Container escape vulnerabilities compromising host OS integrity in shared, multi-tenant AI environments (e.g., CVE-2025-23266).
Command injection and unauthenticated access flaws on core network switches running Cumulus Linux or NVOS.
Privilege escalation and authorization bypasses within DPU management planes (BlueField and the DOCA software stack).
Physical tampering and adjacent network compromise of Edge AI and autonomous vehicle platforms (Jetson/DRIVE) due to insecure default configurations.
Continued weaponization of stolen NVIDIA code-signing certificates by the broader cybercriminal ecosystem to bypass OS security controls.
State-sponsored espionage campaigns systematically targeting semiconductor intellectual property and proprietary GPU architectural designs.
Disruption, interception, or manipulation of East-West GPU training fabrics due to inherent authentication weaknesses in unencrypted RoCE/RDMA deployments.
Exposure of unauthenticated management APIs for high-value AI services (e.g., Riva, AIStore) leading to resource abuse or model theft.
Supply chain compromises introduced via malicious dependencies embedded within open-source ML libraries or container base images.
The geopolitical targeting of NVIDIA's critical R&D facilities and personnel in Israel by hostile nation-states.
Top 10 Most Important Monitoring Priorities:
Anomalous usage of the LD_PRELOAD environment variable within containers executing NVIDIA OCI hooks.
The presence of shell metacharacters or unexpected command formatting in NVUE REST/CLI payloads.
Unauthorized authentication attempts or unusual SSH sessions targeting the out-of-band management IP addresses of BlueField DPUs and Spectrum switches.
Modifications or unauthorized access attempts to ipfilter routing tables on Mellanox/Spectrum hardware.
Execution of unexpected child processes (e.g., wget, curl, bash) spawning from network management daemons.
Installation of Windows hardware drivers utilizing expired or revoked NVIDIA code-signing certificates.
Anomalous outbound data transfers from engineering or R&D network segments indicating potential IP exfiltration.
Unexpected crashes or kernel panics related to the nvidia.ko or nvlddmkm.sys drivers, potentially indicating failed exploitation attempts.
Excessive or anomalous API queries directed at AIStore authentication endpoints.
Unexplained configuration changes or credential modifications within the Omniverse Launcher environment.
Top 10 Most Important Product-Security Recommendations:
Mandate the removal, strict sandboxing, or secure redesign of the enable-cuda-compat OCI hook in container runtimes to prevent escape vectors.
Enforce rigorous input validation, sanitization, and parameterized querying on all NVUE endpoints in Cumulus/NVOS to eradicate command injection flaws.
Accelerate the engineering and deployment of native MACsec, IPsec, and robust encryption/authentication standards for all RDMA and RoCEv2 fabrics.
Ensure all Jetson and DRIVE edge platforms enforce a secure-by-default posture, requiring user-generated credentials and unique machine IDs upon initial boot.
Expand the capabilities of DOCA Argus to not only monitor the AI application layer but to actively hunt for advanced kernel rootkits within the host OS.
Implement mandatory, hardware-backed Multi-Factor Authentication (MFA) and strict network access control lists (ACLs) for all BMC and DPU management interfaces.
Continue expanding the issuance of VEX documentation to assist enterprise customers with accurate, context-aware vulnerability triage.
Systematically deprecate legacy, insecure cryptographic modules and legacy code paths within proprietary display and compute drivers.
Enhance native telemetry export capabilities (e.g., flow logs, execution traces) from Spectrum switches to facilitate the detection of LOTL techniques by SOC teams.
Foster rigorous, continuous internal red-teaming of the DOCA software stack, treating it as the ultimate trust boundary in the zero-trust AI architecture.
Overall Confidence Assessment:
High Confidence is placed in the technical mechanics, severity, and impact of the specific vulnerabilities discussed (corroborated by NVD and official NVIDIA PSIRT advisories), as well as the historical targeting of NVIDIA by the LAPSUS$ extortion group.
Medium Confidence is placed in the assessment that specific state-sponsored APTs (like Volt Typhoon) are directly targeting NVIDIA networking hardware. While the actor's documented Tactics, Techniques, and Procedures (TTPs) strongly align with the exploitation of enterprise switches and edge devices, explicit public attribution confirming the compromise of NVIDIA-branded switches by these specific actors remains an analytic assessment based on prevailing sector trends and capability overlaps.



JSON
{
  "products": [
    "BlueField DPU",
    "DOCA",
    "Spectrum Ethernet switches",
    "Cumulus Linux",
    "NVOS",
    "ConnectX",
    "NVIDIA Container Toolkit",
    "Jetson",
    "Pure SONiC",
    "Omniverse",
    "AIStore"
  ],
  "vulnerabilities": [
    "CVE-2025-23266",
    "CVE-2025-33181",
    "CVE-2025-33179",
    "CVE-2025-23256",
    "CVE-2025-23258",
    "CVE-2026-24148",
    "CVE-2026-24187",
    "CVE-2024-0101",
    "CVE-2024-0104",
    "CVE-2022-28181",
    "CVE-2025-33185",
    "CVE-2025-23289"
  ],
  "threat_actors": [
    "LAPSUS$",
    "Volt Typhoon",
    "UNC3890",
    "APT41",
    "Flax Typhoon"
  ],
  "attack_mappings": [
    {"tactic": "Initial Access", "technique_id": "T1190"},
    {"tactic": "Execution", "technique_id": "T1059.004"},
    {"tactic": "Privilege Escalation", "technique_id": "T1611"},
    {"tactic": "Privilege Escalation", "technique_id": "T1574.006"},
    {"tactic": "Defense Evasion", "technique_id": "T1553.002"},
    {"tactic": "Defense Evasion", "technique_id": "T1014"},
    {"tactic": "Credential Access", "technique_id": "T1003"},
    {"tactic": "Lateral Movement", "technique_id": "T1210"},
    {"tactic": "Exfiltration", "technique_id": "T1567"}
  ],
  "pirs": [
    "Are threat actors actively developing, discussing, or trading exploits for NVIDIA DPU or Switch OS platforms (Cumulus Linux, NVOS, DOCA)?",
    "Are state-sponsored groups (e.g., Volt Typhoon, Flax Typhoon) expanding their edge-device targeting methodology to include NVIDIA Spectrum switches?",
    "Is there evidence of In-the-Wild exploitation of the NVIDIA Container Toolkit vulnerability (CVE-2025-23266 / NVIDIAScape)?",
    "Are semiconductor or AI-focused APT groups (e.g., APT41) demonstrating targeted interest in proprietary GPU microarchitecture, DPU designs, or AI model weights?",
    "Are supply-chain components utilized by NVIDIA products (e.g., Open-source AI libraries, Debian packages in DOCA) affected by newly disclosed software supply chain compromises?"
  ],
  "hunting_hypotheses": [
    "Detect anomalous LD_PRELOAD usage in containers targeting the nvidia-container-toolkit or enable-cuda-compat hook.",
    "Search for shell metacharacters in NVUE REST/CLI payloads indicating command injection.",
    "Monitor for unauthorized access, repeated authentication failures, or privilege escalation on BlueField BMC and DOCA collectx services."
  ],
  "mitigations": [
    "Disable the enable-cuda-compat hook in container runtime configurations.",
    "Restrict NVUE interface access to trusted administrative IP ranges via strict ACLs.",
    "Apply DPU, Switch OS, and GPU driver firmware updates.",
    "Isolate Jetson devices on segmented networks and enforce unique machine IDs.",
    "Deploy IPsec over RoCEv2 or application-layer encryption for RDMA fabrics."
  ],
  "evidence_objects": [
    {
      "claim_id": "CLAIM-001",
      "claim": "NVIDIA Container Toolkit is vulnerable to a container escape flaw allowing arbitrary code execution with elevated permissions (CVE-2025-23266).",
      "source_title": "CVE-2025-23266 Details",
      "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-23266",
      "publisher": "NVD",
      "publication_date": "July 17, 2025",
      "source_type": "cve_nvd",
      "evidence_strength": "Strong",
      "confidence": "High",
      "limitations": "Proof of Concept exists, but massive exploitation in the wild remains unconfirmed."
    },
    {
      "claim_id": "CLAIM-002",
      "claim": "Cumulus Linux and NVOS contain command injection and privilege escalation vulnerabilities in the NVUE interface (CVE-2025-33179, CVE-2025-33181).",
      "source_title": "CVE-2025-33181: NVIDIA Cumulus Linux Privilege Escalation",
      "source_url": "https://www.sentinelone.com/vulnerability-database/cve-2025-33181/",
      "publisher": "SentinelOne",
      "publication_date": "February 27, 2026",
      "source_type": "cti_vendor",
      "evidence_strength": "Strong",
      "confidence": "High",
      "limitations": "None."
    },
    {
      "claim_id": "CLAIM-003",
      "claim": "LAPSUS$ breached NVIDIA in 2022, stealing 1TB of data including source code and code-signing certificates which were subsequently weaponized.",
      "source_title": "NVIDIA breached, code signing certificates stolen",
      "source_url": "https://www.quorumcyber.com/threat-intelligence/nvidia-breached-code-signing-certificates-stolen/",
      "publisher": "Quorum Cyber",
      "publication_date": "2022",
      "source_type": "cti_vendor",
      "evidence_strength": "Strong",
      "confidence": "High",
      "limitations": "None."
    },
    {
      "claim_id": "CLAIM-004",
      "claim": "Volt Typhoon targets critical infrastructure routers and edge devices using living-off-the-land techniques.",
      "source_title": "Volt Typhoon targets US critical infrastructure with living-off-the-land techniques",
      "source_url": "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/",
      "publisher": "Microsoft",
      "publication_date": "May 24, 2023",
      "source_type": "cti_vendor",
      "evidence_strength": "Strong",
      "confidence": "High",
      "limitations": "Specific targeting of NVIDIA-branded switches is inferred via TTPs and sector placement; it is not explicitly documented in the cited report."
    },
    {
      "claim_id": "CLAIM-005",
      "claim": "UNC3890 is an Iranian threat actor targeting Israeli shipping, government, and tech infrastructure.",
      "source_title": "Suspected Iranian Actor Targeting Israeli Shipping",
      "source_url": "https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping/",
      "publisher": "Mandiant",
      "publication_date": "2022",
      "source_type": "cti_vendor",
      "evidence_strength": "Strong",
      "confidence": "High",
      "limitations": "Direct targeting of NVIDIA facilities in Israel is not explicitly proven, but they operate heavily in the targeted sector and region."
    },
    {
      "claim_id": "CLAIM-006",
      "claim": "BlueField DPUs contain management interface authorization flaws (CVE-2025-23256).",
      "source_title": "CVE-2025-23256 Detail",
      "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-23256",
      "publisher": "NVD",
      "publication_date": "September 4, 2025",
      "source_type": "cve_nvd",
      "evidence_strength": "Strong",
      "confidence": "High",
      "limitations": "None."
    },
    {
      "claim_id": "CLAIM-007",
      "claim": "RDMA and RoCEv2 inherently lack encryption and robust authentication, enabling packet injection and unauthorized memory access (ReDMArk).",
      "source_title": "ReDMArk: Bypassing RDMA Security in Data Centers",
      "source_url": "https://www.usenix.org/system/files/sec21-rothenberger.pdf",
      "publisher": "USENIX Security",
      "publication_date": "2021",
      "source_type": "research",
      "evidence_strength": "Medium",
      "confidence": "Medium",
      "limitations": "Demonstrated primarily as a proof-of-concept in academic research; active wild exploitation by APTs remains unconfirmed."
    }
  ]
}


Works cited
NVIDIA Data Breach - Feb 2022, https://breach-hq.com/breaches/nvidia/2022-feb
Hackers and NVIDIA battle it out after ransomware hack - Cylynt, https://cylynt.com/insights/hackers-and-nvidia-battle-it-out/
Malware Made Look Trustworthy through Stolen NVIDIA Code Signing Certificates, https://heimdalsecurity.com/blog/nvidia-code-signing-certificates-leveraged-to-sign-malware/
[Update]Detailed Analysis of LAPSUS$ Cybercriminal Group that has Compromised Nvidia, Microsoft, Okta, and Globant | CloudSEK, https://www.cloudsek.com/blog/profile-lapsus-cybercriminal-group
Understanding the NVIDIAScape (CVE‑2025‑23266) Container Toolkit Vulnerability - and Why Your AI Workloads Are Most Likely Safe - Upwind Security, https://www.upwind.io/feed/understanding-the-nvidiascape-cve%E2%80%912025%E2%80%9123266-container-toolkit-vulnerability-and-why-your-ai-workloads-are-most-likely-safe
CVE-2025-23266: NVIDIA Toolkit Flaw | Fidelis Security, https://fidelissecurity.com/vulnerabilities/cve-2025-23266/
NVIDIAScape: Breaking Container Isolation with CVE-2025-23266 in NVIDIA Container Toolkit - ZeroPath Blog, https://zeropath.com/blog/nvidiascape-cve-2025-23266-nvidia-container-toolkit-escape
NVIDIAScape CVE-2025-23266: Critical NVIDIA Container Escape Vulnerability | Patch Now - SOSECURE, https://www.sosecure.co.th/en/activity/nvidiascape-vulnerability-cve-2025-23266-in-nvidia-container-toolkit-threatens-docker-and-kubernetes-environments
CVE-2025-33181: NVIDIA Cumulus Linux Privilege Escalation - SentinelOne, https://www.sentinelone.com/vulnerability-database/cve-2025-33181/
CVE-2025-33179 Detail - NVD, https://nvd.nist.gov/vuln/detail/CVE-2025-33179
CVE-2025-23256 Detail - NVD, https://nvd.nist.gov/vuln/detail/CVE-2025-23256
NVIDIA DOCA contains a vulnerability in the collectx... · CVE-2025-23257 - GitHub, https://github.com/advisories/ghsa-v389-cff2-r6c9
NVIDIA BlueField contains a vulnerability in the... · CVE-2025-23256 - GitHub, https://github.com/advisories/GHSA-cf8m-72r3-jm23
CVE-2025-23258 - CVE Record, https://www.cve.org/CVERecord?id=CVE-2025-23258
CVE-2025-23258 Detail - NVD, https://nvd.nist.gov/vuln/detail/CVE-2025-23258
China-Linked Threat Groups Target AI Infrastructure in 58% o - Tech Jacks Solutions, https://techjacksolutions.com/scc-intel/china-linked-threat-groups-target-ai-infrastructure-in-58-of-state-sponsored-tech-sector-attacks/
2025 APT Report: Staying Ahead of the Modern Threat Landscape | Trend Micro (US), https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/2025-apt-report-staying-ahead-of-the-modern-threat-landscape
Volt Typhoon - Wikipedia, https://en.wikipedia.org/wiki/Volt_Typhoon
U.S. Government Disrupts Botnet People's Republic of China Used to Conceal Hacking of Critical Infrastructure - Department of Justice, https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical
Volt Typhoon - NJCCIC - NJ.gov, https://www.cyber.nj.gov/threat-landscape/nation-state-threat-analysis-reports/china-linked-cyber-operations-targeting-us-critical-infrastructure/volt-typhoon
Mellanox magic: The secret behind Nvidia's meteoric trillion-dollar rise | Ctech, https://www.calcalistech.com/ctechnews/article/150f7k0t5
NVIDIA to Acquire Mellanox for $6.9 Billion, https://nvidianews.nvidia.com/news/nvidia-to-acquire-mellanox-for-6-9-billion
UNC3890 (Threat Actor) - Malpedia, https://malpedia.caad.fkie.fraunhofer.de/actor/unc3890
UNC3890: Suspected Iranian Threat Actor Targeting Israeli Shipping, Healthcare, Government and Energy Sectors | Google Cloud Blog, https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping/
NeVerMore: Exploiting RDMA Mistakes in NVMe-oF Storage Applications - SNIA, https://www.snia.org/sites/default/files/Security-Summit/2022/SNIA-SSS22-Taranov-NeVerMore-Exploiting-RDMA-Mistakes.pdf
Bypassing RDMA Security Mechanisms - ReDMArk - USENIX, https://www.usenix.org/system/files/sec21-rothenberger.pdf
Bedrock: Programmable Network Support for Secure RDMA Systems - Jiarong Xing, https://jxing.me/slides/UsenixSecurity22-Bedrock.pdf
CVE-2026-24148 Detail - NVD, https://nvd.nist.gov/vuln/detail/CVE-2026-24148
CVE-2026-24148: NVIDIA Jetson Information Disclosure Flaw - SentinelOne, https://www.sentinelone.com/vulnerability-database/cve-2026-24148/
Advancing AI Infrastructure for Agentic AI with NVIDIA DOCA In-Silicon Security, https://developer.nvidia.com/blog/advancing-ai-infrastructure-for-agentic-ai-with-nvidia-doca-in-silicon-security/
For WEKA and NVIDIA, Securing Agentic AI Starts at the Data Layer, https://www.weka.io/article/for-weka-and-nvidia-securing-agentic-ai-starts-at-the-data-layer
NVIDIA Vera BlueField-4 STX Brings Agentic AI Storage Processing With In-Silicon Security, https://nvidianews.nvidia.com/news/nvidia-vera-bluefield-4-stx-brings-agentic-ai-storage-processing-with-in-silicon-security
NVIDIA BlueField Networking Platform, https://www.nvidia.com/en-au/networking/products/data-processing-unit/
DOCA Software Framework - NVIDIA Developer, https://developer.nvidia.com/networking/doca
CVE-2024-0101: Nvidia Mlnx-os DOS Vulnerability - SentinelOne, https://www.sentinelone.com/vulnerability-database/cve-2024-0101/
Security Updates – NVIDIA Tracking #:432316084 Date:24-07-2024 - ADGM, https://www.adgm.com/documents/financial-crime-prevention-unit/cybercrime-prevention/20240724-cyber-security-council-alert-320.pdf
NVIDIA GPUDirect Storage (GDS): The VAST Data Story, https://www.vastdata.com/blog/nvidia-gpu-direct-for-storage-gds-the-vast-data-story
GPUDirect RDMA and GPUDirect Storage — NVIDIA GPU Operator, https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-operator-rdma.html
Missing Authorization in github.com/nvidia/aistore/api/authn | CVE-2025-33185 | Snyk, https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMNVIDIAAISTOREAPIAUTHN-13893812
Vulnerability Response — NVIDIA AI Enterprise Security White Paper, https://docs.nvidia.com/ai-enterprise/planning-resource/ai-enterprise-security-white-paper/latest/vulnerability-response.html
Omniverse Launcher Security Update: Please Update to v1.9.19, https://forums.developer.nvidia.com/t/omniverse-launcher-security-update-please-update-to-v1-9-19/340991
NVIDIA Omniverse Launcher for Windows and Linux contains... · CVE-2025-23289 - GitHub, https://github.com/advisories/GHSA-7hhp-cmgc-52fj
Canonical and NVIDIA BlueField-4: a foundation for zero-trust high performance infrastructure | Ubuntu, https://ubuntu.com/blog/canonical-and-nvidia-bluefield-4-a-foundation-for-zero-trust-high-performance-infrastructure
Reinventing Security for the Agentic NVIDIA AI Factory - Palo Alto Networks, https://www.paloaltonetworks.com/blog/2026/06/reinventing-security-for-the-agentic-nvidia-ai-factory/
RDMA over Converged Ethernet (RoCE) - NVIDIA Docs, https://docs.nvidia.com/networking/display/mlnxofedv23103220lts/rdma+over+converged+ethernet+(roce)
MinIO AIStor with NVIDIA GPUDirect® RDMA for S3-Compatible Storage: Unlocking Performance for AI Factory Workloads, https://www.min.io/blog/minio-aistor-with-nvidia-gpudirect-r-rdma-for-s3-compatible-storage-unlocking-performance-for-ai-factory-workloads
Securing RDMA for High-Performance Datacenter Storage Systems | USENIX, https://www.usenix.org/system/files/hotcloud20_paper_simpson.pdf
CVE-2025-23266 Detail - NVD, https://nvd.nist.gov/vuln/detail/cve-2025-23266
CVE-2025-33181 - vulnerability database, https://vulners.com/cve/CVE-2025-33181
Nvidia vulnerability, impact on 4000-series cards : r/pcmasterrace - Reddit, https://www.reddit.com/r/pcmasterrace/comments/1tjqk2f/nvidia_vulnerability_impact_on_4000series_cards/
Nvidia CVEs and Security Vulnerabilities - OpenCVE, https://app.opencve.io/cve/?vendor=nvidia
CVE-2022-28181: Nvidia Virtual GPU RCE Vulnerability - SentinelOne, https://www.sentinelone.com/vulnerability-database/cve-2022-28181/
Stolen Nvidia certificates used to sign malware—here's what to do - ThreatDown, https://www.threatdown.com/blog/stolen-nvidia-certificates-used-to-sign-malware-heres-what-to-do/
Threat groups using stolen Nvidia certificates to sign malware - Computing UK, https://www.computing.co.uk/news/4046067/threat-stolen-nvidia-certificates-sign-malware
CVE-2023-25516: Nvidia GPU Display Driver Vulnerability - SentinelOne, https://www.sentinelone.com/vulnerability-database/cve-2023-25516/
Security - NVIDIA/aicr - GitHub, https://github.com/NVIDIA/aicr/security
Security - NVIDIA/NVSentinel - GitHub, https://github.com/NVIDIA/NVSentinel/security
Lapsus$ - Wikipedia, https://en.wikipedia.org/wiki/Lapsus$
Nvidia Hit by Major Cyberattack | Hacker News, https://news.ycombinator.com/item?id=30476181
NVIDIA Riva Vulnerabilities Leave AI-Powered Speech and Translation Services at Risk, https://www.trendmicro.com/en_us/research/25/d/nvidia-riva-vulnerabilities.html
Volt Typhoon targets US critical infrastructure with living-off-the-land techniques - Microsoft, https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
UNC3890 Iranian hacker activity primarily targets Israeli shipping, government, energy, healthcare organizations - Industrial Cyber, https://industrialcyber.co/news/unc3890-iranian-hacker-activity-primarily-targets-israeli-shipping-government-energy-healthcare-organizations/
APT groups and threat actors - Google Cloud, https://cloud.google.com/security/resources/insights/apt-groups
apt41.pdf - HHS.gov, https://www.hhs.gov/sites/default/files/apt41.pdf
The conflict between Nvidia and Ransomware Group Lapsus - About UCalgary WordPress, https://wpsites.ucalgary.ca/isec-601-f21/2022/03/03/the-conflict-between-nvidia-and-ransomware-group-lapsus/
AI Chip Supply Chain Risk 2026: Your Essential Guide - Enki AI, https://enkiai.com/ai-market-intelligence/ai-chip-supply-chain-risk-2026-your-essential-guide/
The Latent Storm: Volt Typhoon and Supply Chain Vulnerabilities | TXOne Networks, https://www.txone.com/blog/volt-typhoon-and-supply-chain-vulnerabilities/
How to attract a $4 trillion company? NVIDIA prompts Israeli frenzy - Israel & Jewish News, https://www.jns.org/israel-news/how-to-attract-a-4-trillion-company-nvidia-prompts-israeli-frenzy
Israel proposes Kiryat Tivon for Nvidia's multibillion-dollar tech campus in north, https://www.timesofisrael.com/israel-proposes-kiryat-tivon-for-nvidias-multibillion-dollar-tech-campus-in-north/
Nvidia lands in Kiryat Tivon, turning pioneer hills into Israel's next tech battlegro - Ynet News, https://www.ynetnews.com/business/article/hks8pjwbwx
Advanced threat predictions for 2026 - Kaspersky, https://lp.kaspersky.com/global/ksb2025-apt-predictions/
Chinese APTs running persistent campaign target critical infrastructure, telecom networks, https://industrialcyber.co/news/chinese-apts-running-persistent-campaign-target-critical-infrastructure-telecom-networks/
