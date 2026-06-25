# Volt Typhoon: US Critical Infrastructure Threat Report
Source: Microsoft Security Blog — May 24, 2023
URL: https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/

## Executive Summary

Microsoft Threat Intelligence identified a Chinese state-sponsored actor targeting US critical infrastructure through "living-off-the-land techniques." The report states: "Volt Typhoon, a state-sponsored actor based in China...is pursuing development of capabilities that could disrupt critical communications infrastructure."

## Threat Actor Profile

**Active Since:** Mid-2021
**Attribution:** China-based, state-sponsored entity
**Motivation:** Espionage and information gathering with emphasis on maintaining undetected access
**Targeted Sectors:** Communications, manufacturing, utilities, transportation, construction, maritime, government, IT, and education

## Initial Access Vector

Volt Typhoon exploits internet-facing Fortinet FortiGuard devices. The actor extracts Active Directory credentials and attempts lateral movement across target networks.

The group routes traffic through compromised SOHO equipment from manufacturers including "ASUS, Cisco, D-Link, NETGEAR, and Zyxel" to obscure operations.

## Post-Compromise Tactics

### Credential Access
- LSASS memory dumping for OS credential hashes
- Ntdsutil usage to create domain controller installation media containing password hashes
- Offline cracking of extracted credentials for persistence

### Discovery
Command-line reconnaissance of systems, file systems, running processes, and network topology using PowerShell, WMIC, and ping utilities.

### Collection
Browser credential harvesting and staging data in password-protected archives.

### Command and Control
- Primary method: Valid credential-based authentication
- Secondary methods: netsh portproxy port forwarding; custom versions of Impacket and Fast Reverse Proxy (FRP) tools

## Detection Signatures

**Microsoft Defender Antivirus alerts:**
- Behavior:Win32/SuspNtdsUtilUsage.A
- Behavior:Win32/SuspPowershellExec.E
- Behavior:Win32/WmiSuspProcExec.J!se

**Microsoft 365 Defender:**
- "Volt Typhoon threat actor detected"
- Ntdsutil Active Directory collection
- LSASS password hash dumping
- Suspicious wmic.exe code execution

## Hunting Queries

**Domain Controller Media Creation:**
```
DeviceProcessEvents | where ProcessCommandLine has_all ("ntdsutil", "create full", "pro")
```

**Internal Proxy Establishment:**
```
DeviceProcessEvents | where ProcessCommandLine has_all ("portproxy", "netsh", "wmic", "process call create", "v4tov4")
```

## Mitigation Recommendations

**Account Protection:**
- Enforce multi-factor authentication with hardware security keys
- Implement passwordless sign-in
- Deactivate unused accounts
- Apply password expiration policies

**Attack Surface Reduction Rules:**
- Block credential stealing from LSASS
- Block PSExec and WMI-originated process creation
- Block potentially obfuscated script execution

**Advanced Defenses:**
- Enable Protective Process Light (PPL) for LSASS on Windows 11
- Deploy Windows Defender Credential Guard
- Enable cloud-delivered protection in Microsoft Defender Antivirus
- Run endpoint detection and response (EDR) in block mode

## Indicators of Compromise

**Custom FRP Executable SHA-256 Hashes (selected):**
- baeffeb5fdef2f42a752c65c2d2a52e84fb57efc906d981f89dd518c314e231c
- b4f7c5e3f14fb57be8b5f020377b993618b6e3532a4e1eb1eae9976d4130cc74

## Additional Resources

- NSA published a complementary Cybersecurity Advisory with hunting guidance
- Microsoft 365 Defender provides automated detection
- Microsoft Sentinel queries available for LSASS dumping, Impacket execution, and proxy establishment

**Publication Date:** May 24, 2023
