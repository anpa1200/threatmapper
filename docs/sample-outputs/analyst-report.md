# AdversaryGraph Demo Analyst Report

## Summary

The synthetic demo report describes phishing attachment delivery, PowerShell execution, discovery, credential dumping from LSASS, SMB lateral movement, archive staging, and HTTPS transfer.

## Accepted ATT&CK Mappings

| Technique | Name | Confidence | Evidence |
|---|---|---:|---|
| T1566.001 | Spearphishing Attachment | 0.95 | phishing email with malicious archive attachment |
| T1059.001 | PowerShell | 0.94 | launched PowerShell with encoded commands |
| T1003.001 | LSASS Memory | 0.93 | dumped credentials from LSASS memory |
| T1021.002 | SMB/Windows Admin Shares | 0.78 | connection to file server over SMB |
| T1560.001 | Archive via Utility | 0.76 | compressed documents into password-protected archive |

## Detection Gaps

- Confirm email gateway visibility for attachment delivery.
- Validate encoded PowerShell detection against administrator baselines.
- Validate LSASS access detection with EDR telemetry.
- Review SMB session telemetry for lateral movement.
- Add archive staging hunt logic before production detection.

## Limitations

This is a synthetic demo. ATT&CK mappings are examples of the review workflow and are not attribution evidence.
