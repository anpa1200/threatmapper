# LAPSUS$ NVIDIA Breach (2022) — Certificate Theft and Weaponisation
Sources: Heimdal Security, Quorum Cyber, CloudSEK, multiple security researchers

## The Breach

The Lapsus$ threat group compromised NVIDIA's corporate network (February 2022),
exfiltrating approximately 1TB of proprietary data including:
- Hardware schematics and GPU architectural documentation
- GPU driver source code
- Two code-signing certificates used by NVIDIA developers
- 71,000 employee credential hashes
- Proprietary source code and internal tools

Lapsus$ demanded NVIDIA open-source its GPU drivers and remove Lite Hash Rate (LHR)
cryptocurrency mining limiters from RTX 30-series GPUs. When demands were refused,
data was leaked publicly via Telegram.

## Stolen Code-Signing Certificates

Two certificates were exfiltrated. Despite being expired, Windows still permitted
them to be used for driver signing purposes (noted by researcher Bill Demirkapi).

**Compromised certificate serial numbers:**
- 43BB437D609866286DD839E1D00309F5
- 14781bc862e8dc503a559346f5dcc518

## How Certificates Were Weaponised

Within days of the LAPSUS$ leak, the broader criminal ecosystem adopted the stolen
certificates to sign malicious software, making it appear as legitimate NVIDIA hardware
drivers and bypassing Windows Defender Application Control and driver signature enforcement.

**Malware families signed with stolen NVIDIA certificates:**
- Mimikatz (credential dumping)
- Cobalt Strike beacons (post-exploitation C2)
- Quasar RAT (remote access trojan)
- Various backdoors and kernel-mode rootkits

## MITRE ATT&CK Techniques (LAPSUS$)

| Technique | Description |
|---|---|
| T1553.002 | Subvert Trust Controls: Code Signing |
| T1566 | Phishing (initial access) |
| T1078 | Valid Accounts (insider bribery for initial access) |
| T1537 | Transfer Data to Cloud Account |
| T1567 | Exfiltration Over Web Service (Telegram) |

## Ongoing Relevance (2026)

The weaponised NVIDIA certificates continue to circulate in the criminal ecosystem.
Any endpoint that encounters a driver signed with these specific serial numbers should
be treated as potentially compromised.

**Detection query (Windows Event Log):**
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Where-Object { $_.Message -match '43BB437D609866286DD839E1D00309F5|14781bc862e8dc503a559346f5dcc518' }
```

**Defensive action (WDAC policy):** Deploy Windows Defender Application Control
policies to block drivers signed with revoked NVIDIA certificate serial numbers.

## Downstream Intelligence Value

- 71,000 employee credential hashes leaked: monitor for nvidia.com domain credentials
  in breach databases
- Source code disclosure may have enabled discovery of zero-days exploited later
- Certificate abuse pattern demonstrates that NVIDIA-branded code-signing is a
  high-value criminal asset

## References
- Heimdal Security: https://heimdalsecurity.com/blog/nvidia-code-signing-certificates-leveraged-to-sign-malware/
- Quorum Cyber: https://www.quorumcyber.com/threat-intelligence/nvidia-breached-code-signing-certificates-stolen/
- CloudSEK: https://www.cloudsek.com/blog/profile-lapsus-cybercriminal-group
- ThreatDown: https://www.threatdown.com/blog/stolen-nvidia-certificates-used-to-sign-malware-heres-what-to-do/
- Wikipedia Lapsus$: https://en.wikipedia.org/wiki/Lapsus$
