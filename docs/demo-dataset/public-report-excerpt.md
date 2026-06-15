# Demo Report Excerpt

This synthetic public-style excerpt is safe demo data. It is not a real victim report.

## Scenario

A financially motivated intrusion set targeted a regional manufacturing company. The initial access vector was a phishing email with a malicious archive attachment. The archive contained a script that launched PowerShell with encoded commands. After execution, the operator used command-line discovery to enumerate the local host, domain trust information, running processes, and network shares.

The operator dumped credentials from LSASS memory and reused valid domain credentials to connect to a file server over SMB. On the file server, the operator compressed selected documents into a password-protected archive and staged the archive in a temporary directory. The archive was later transferred to an external HTTPS endpoint.

## Evidence Notes

- Phishing attachment delivered initial payload.
- PowerShell encoded commands executed after user interaction.
- Discovery commands included host, process, domain, and share enumeration.
- LSASS memory access was observed before lateral movement.
- SMB was used for remote access to the file server.
- Files were compressed before outbound HTTPS transfer.

## Expected ATT&CK Candidates

This demo should produce candidates similar to:

- `T1566.001` Spearphishing Attachment
- `T1059.001` PowerShell
- `T1082` System Information Discovery
- `T1057` Process Discovery
- `T1087.002` Domain Account
- `T1135` Network Share Discovery
- `T1003.001` LSASS Memory
- `T1021.002` SMB/Windows Admin Shares
- `T1560.001` Archive via Utility
- `T1041` Exfiltration Over C2 Channel

Mappings require analyst review before use.
