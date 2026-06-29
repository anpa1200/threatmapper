# Demo CTI Report Excerpt

An intrusion cluster used password spraying against a public VPN portal and later authenticated successfully with a valid account. The actor enumerated internal web paths, attempted SQL injection canaries against a legacy admin endpoint, and staged discovery commands from a Windows workstation.

After initial access, the operator launched PowerShell with encoded content, queried domain trust relationships, and attempted credential access by opening LSASS with dump-capable access rights. The same host later used `rundll32.exe` to proxy execution of a remote scriptlet.

Observed indicators:

- `login-gateway.demo.example`
- `updates-demo.example`
- `198.51.100.42`
- `203.0.113.77`
- `https://updates-demo.example/payload.dat`
- `5f6d7c8b9a00112233445566778899aabbccddeeff00112233445566778899aa`

Analyst note: this sample report is intentionally synthetic and safe. It is designed to trigger deterministic ATT&CK candidates and IOC extraction for product evaluation.
