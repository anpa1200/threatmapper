# Expected Demo Report Shape

## Summary

The sample describes a credential-based intrusion path beginning with password spraying against a public VPN, followed by successful valid-account access, web reconnaissance/exploit canaries, endpoint discovery, credential access, and signed binary proxy execution.

## Expected ATT&CK Leads

- T1110.003 Password Spraying
- T1078 Valid Accounts
- T1190 Exploit Public-Facing Application
- T1059.001 PowerShell
- T1482 Domain Trust Discovery
- T1003.001 LSASS Memory
- T1218.011 Rundll32

## Expected Validation Notes

- Treat all mappings as candidates until the analyst accepts evidence.
- Similarity to any actor profile is not attribution.
- Demo telemetry is safe synthetic reviewer data, not a real compromise.
