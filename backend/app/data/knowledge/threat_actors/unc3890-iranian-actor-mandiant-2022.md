# UNC3890: Suspected Iranian Threat Actor Targeting Israeli Shipping
Source: Mandiant / Google Cloud Threat Intelligence — 2022
URL: https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping/

## Overview

UNC3890 is a suspected Iranian threat actor group targeting Israeli organizations since late 2020. The group focuses on intelligence collection across shipping, healthcare, government, and energy sectors.

## Attribution Indicators

- **Farsi language artifacts** in malware (words like "KHODA" meaning "God" and "yaal" meaning "horse's mane")
- **Focused targeting of Israeli entities**, consistent with other Iranian threat actors
- **Shared PDB paths** with UNC2448 (Iranian IRGC-affiliated group)
- **Use of NorthStar C2 Framework** (preferred by Iranian actors, though publicly available)

## Attack Lifecycle

### Initial Access Methods

1. **Watering holes** — Compromised Israeli shipping company login pages
2. **Credential harvesting** — Fake login pages masquerading as:
   - LinkedIn (lirıkedin[.]com)
   - Office 365 (office365update[.]live)
   - Facebook (rnfacebook[.]com)
3. **Phishing lures** — Fake job offers and AI robotic doll commercials

### Proprietary Malware

**SUGARUSH Backdoor**
- Establishes reverse TCP shell to hardcoded C2 address
- Creates "Service1" service for persistence
- Executes CMD commands
- Communicates via port 4585

**SUGARDUMP Credential Stealer (Multiple Versions)**
- Extracts credentials from Chrome, Edge, Opera, Firefox browsers
- Early version (2021): Local storage only
- SMTP version (late 2021–early 2022): Exfiltrates via Gmail/Yahoo/Yandex
- HTTP version (April 2022): AES-CBC encrypted exfiltration to C2 servers
- Harvests: credentials, browsing history, bookmarks, cookies

### Supporting Tools
- Metasploit framework
- NorthStar C2
- UNICORN (PowerShell downgrade attacks)

## Key Infrastructure

**C2 Servers:**
- 128.199.6[.]246
- 161.35.123[.]176
- 144.202.123[.]248

**Fake Domains (defanged):**
- naturaldolls[.]store
- xxx-doll[.]com
- pfizerpoll[.]com
- celebritylife[.]news
- lirıkedin[.]com
- office365update[.]live
- rnfacebook[.]com

## MITRE ATT&CK Techniques

| Technique ID | Name |
|---|---|
| T1566 | Phishing |
| T1587 | Develop Capabilities |
| T1555.003 | Credentials from Web Browsers |
| T1053.005 | Scheduled Tasks |
| T1102.002 | Web Service C2 |

## NVIDIA Relevance

UNC3890 is highly relevant to NVIDIA's threat model due to:
- NVIDIA's Mellanox R&D facilities based in Yokneam, Israel
- Planned expansion to Kiryat Tivon campus (160,000 sq m)
- Israel-1 supercomputer deployment
- UNC3890's consistent targeting of Israeli technology, energy, and shipping sectors
- High strategic value of NVIDIA networking IP to Iranian state interests

**Confidence:** High for sector/geographic relevance; indirect for direct NVIDIA facility targeting
