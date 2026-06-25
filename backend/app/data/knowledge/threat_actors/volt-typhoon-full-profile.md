# Volt Typhoon — Full Threat Actor Profile
Sources: Wikipedia, Microsoft, CISA, CrowdStrike, Secureworks, Mandiant
Last updated: June 2026

## Identity

**Attribution:** People's Republic of China — People's Liberation Army Cyberspace Force
**Active since:** At least mid-2021
**Primary motivation:** Pre-positioning for disruption of US critical infrastructure
  communications in the event of a military conflict (specifically, US-China Taiwan scenario)

**Industry designations:**
| Vendor | Name |
|---|---|
| Microsoft | Volt Typhoon / Dev-0391 / Storm-0391 |
| CrowdStrike | VANGUARD PANDA |
| Secureworks | BRONZE SILHOUETTE |
| Palo Alto Networks | Insidious Taurus |
| Mandiant/Google | UNC3236 |
| Dragos | VOLTZITE |
| Gen Digital | Redfly |

## Strategic Intent

US government officials assess Volt Typhoon's primary objective is to pre-position
within US critical infrastructure to disrupt communications between the US mainland
and the Asia-Pacific in the event of a conflict, specifically designed to impede
American military mobilization in response to a potential Chinese invasion of Taiwan.

Unlike typical espionage actors, Volt Typhoon is assessed as having a **destructive
disruption** mandate rather than pure intelligence collection.

## Tactics, Techniques, and Procedures (TTPs)

### Living Off the Land (LOTL)
Core characteristic. Uses only built-in Windows/Linux tools, avoids deploying
custom malware. Tools used include:
- wmic, ntdsutil, netsh, PowerShell
- Built-in credential extraction via LSASS
- Legitimate administrative accounts for lateral movement

This approach minimises detection footprint and avoids triggering endpoint security.

### Initial Access
- Exploitation of vulnerable internet-facing devices (Fortinet FortiGuard, Cisco,
  ASUS, D-Link, Netgear, Zyxel edge devices)
- Weak administrator credentials, factory default logins, unpatched systems
- Compromise of SOHO routers for proxy infrastructure (KV Botnet)

### Credential Access
- LSASS memory dumping for OS credential hashes
- Ntdsutil for AD domain controller credential extraction
- Offline cracking of extracted credential hashes

### Command and Control
- Routes traffic through compromised SOHO devices to obscure origins
- KV Botnet: network of compromised SOHO routers used as proxy infrastructure
- Custom versions of Impacket and Fast Reverse Proxy (FRP)
- Legitimate account access as primary C2 mechanism

### Persistence
- Valid account access (T1078) as primary persistence mechanism
- Avoids deploying persistent malware to reduce detection footprint

## MITRE ATT&CK Mapping

| Technique ID | Name | Usage |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial access via edge devices |
| T1078 | Valid Accounts | Primary C2 and persistence |
| T1003.001 | LSASS Memory Dump | Credential harvesting |
| T1040 | Network Sniffing | Traffic capture on compromised devices |
| T1090 | Proxy | KV Botnet proxy infrastructure |
| T1059.001 | PowerShell | LOTL execution |
| T1087 | Account Discovery | Reconnaissance |
| T1110 | Brute Force | Initial access attempt |

## Notable Confirmed Incidents

- **US Guam military infrastructure** (detected 2023): Pre-positioning in critical
  communications systems
- **Singtel breach** (June 2024): Singapore's largest telecom; malware eradicated
- **Australia telecom reconnaissance** (reported November 2025): ASD/ACSC confirmed
  attempted access to Australian critical telecom networks

## Government Actions

- **FBI disruption** (January 2024): Court-authorized removal of malware from
  compromised US routers; KV Botnet partially dismantled
- **CISA/NSA/FBI joint advisory** (May 2023): AA23-144A — public attribution and
  hunting guidance
- **Five Eyes advisory** (February 2024): AA24-038A — multi-nation joint advisory
- **Chinese "tacit admission"** (2024 bilateral meeting): US delegation interpreted
  Chinese counterpart remarks as indirect acknowledgement of involvement

## NVIDIA / AI Infrastructure Relevance

Volt Typhoon's documented TTPs directly align with NVIDIA networking product attack surfaces:

1. **Network edge device compromise**: Spectrum switches and Cumulus Linux are
   functionally identical to documented Volt Typhoon targets (Cisco, Fortinet routers)
2. **Management plane access**: NVUE and BlueField BMC are equivalent to the router
   management interfaces Volt Typhoon historically exploits
3. **LOTL on Linux network OS**: Cumulus Linux's Linux base makes it an ideal LOTL
   environment — standard Linux tools available
4. **Long-dwell passive collection**: AI training traffic (GPU-to-GPU RDMA) traversing
   compromised switches would be invisible to host-based monitoring

**Confidence for NVIDIA-specific targeting:** Medium — documented TTPs match perfectly,
but no public confirmed incident on NVIDIA-branded hardware as of June 2026.

## Detection Signatures

**Microsoft Defender Antivirus:**
- Behavior:Win32/SuspNtdsUtilUsage.A
- Behavior:Win32/SuspPowershellExec.E
- Behavior:Win32/WmiSuspProcExec.J!se

**Splunk hunting (Cumulus Linux / NVOS adaptation):**
```
index=network_device sourcetype=cumulus_syslog
| search process IN ("ntdsutil","wmic","netsh","powershell")
| stats count by host, process, user
| where count > 2 AND user!="admin"
```

## References

- Microsoft (May 2023): https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
- Wikipedia: https://en.wikipedia.org/wiki/Volt_Typhoon
- DOJ Press Release: https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical
- NJCCIC Profile: https://www.cyber.nj.gov/threat-landscape/nation-state-threat-analysis-reports/china-linked-cyber-operations-targeting-us-critical-infrastructure/volt-typhoon
