from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TelemetryReadiness:
    required_data_components: list[str]
    available_logs: list[str]
    missing_telemetry: list[str]
    detection_feasibility: str
    readiness_score: int
    gaps: list[str]


_SOURCE_TO_COMPONENTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("process", ("Process Creation", "Command Execution")),
    ("command", ("Command Execution",)),
    ("script", ("Script Block Logging", "Command Execution")),
    ("module", ("Module Load",)),
    ("image", ("Process Creation", "Module Load")),
    ("file", ("File Creation", "File Modification", "File Deletion")),
    ("registry", ("Registry Key Modification", "Registry Value Modification")),
    ("network", ("Network Connection", "Network Flow")),
    ("netflow", ("Network Flow",)),
    ("dns", ("DNS Query",)),
    ("domain", ("DNS Query",)),
    ("web", ("HTTP Request", "Web Server Access Log")),
    ("proxy", ("Proxy Request",)),
    ("authentication", ("Logon Event", "Authentication Event")),
    ("logon", ("Logon Event",)),
    ("user account", ("Account Management",)),
    ("cloud", ("Cloud Audit Event",)),
    ("container", ("Container Audit Event",)),
    ("service", ("Service Creation", "Service Modification")),
    ("scheduled task", ("Scheduled Task Event",)),
    ("wmi", ("WMI Activity",)),
    ("driver", ("Driver Load",)),
    ("kernel", ("Kernel Object Access",)),
    ("memory", ("Memory Allocation", "Process Access")),
)

_TACTIC_COMPONENTS: dict[str, tuple[str, ...]] = {
    "execution": ("Process Creation", "Command Execution"),
    "persistence": ("Service Creation", "Scheduled Task Event", "Registry Key Modification", "File Creation"),
    "privilege-escalation": ("Process Creation", "Token/Privilege Use", "Service Modification"),
    "defense-evasion": ("Process Creation", "File Modification", "Registry Key Modification"),
    "credential-access": ("Process Access", "Authentication Event", "Registry Access"),
    "discovery": ("Process Creation", "Command Execution", "Network Connection"),
    "lateral-movement": ("Logon Event", "Network Connection", "Remote Service Creation"),
    "collection": ("File Access", "Process Creation"),
    "command-and-control": ("Network Connection", "DNS Query", "Proxy Request"),
    "exfiltration": ("Network Connection", "Proxy Request", "File Read", "Large Upload"),
    "initial-access": ("HTTP Request", "Authentication Event", "Network Connection"),
    "reconnaissance": ("HTTP Request", "DNS Query", "Network Flow"),
    "impact": ("Process Creation", "File Modification", "Service Modification"),
}

_TECHNIQUE_OVERRIDES: dict[str, tuple[str, ...]] = {
    "T1059": ("Process Creation", "Command Execution"),
    "T1059.001": ("Process Creation", "Command Execution", "Script Block Logging", "Module Load"),
    "T1059.003": ("Process Creation", "Command Execution"),
    "T1003": ("Process Access", "Process Creation", "Credential Store Access"),
    "T1003.001": ("Process Access", "LSASS Access", "Module Load"),
    "T1110": ("Authentication Event", "Logon Failure", "Logon Success"),
    "T1110.001": ("Authentication Event", "Logon Failure", "Source IP/User Correlation"),
    "T1078": ("Logon Event", "Account Context", "Authentication Success"),
    "T1190": ("HTTP Request", "Web Server Access Log", "WAF/Security Alert"),
    "T1505.003": ("HTTP File Upload", "Web Server Access Log", "File Creation", "Process Creation"),
    "T1071": ("Network Connection", "DNS Query", "Proxy Request"),
    "T1071.001": ("HTTP Request", "Proxy Request", "DNS Query"),
    "T1041": ("Network Connection", "Proxy Request", "Large Upload"),
    "T1046": ("Network Flow", "Firewall Traffic", "Connection Attempt"),
    "T1053": ("Scheduled Task Event", "Process Creation"),
    "T1053.005": ("Windows Security 4698", "Scheduled Task Event", "Process Creation"),
    "T1068": ("Process Creation", "Exploit Telemetry", "Kernel/EDR Alert"),
    "T1105": ("Network Connection", "File Creation", "Process Creation"),
    "T1562": ("Service Modification", "Registry Key Modification", "EDR Tamper Alert"),
    "T1564": ("File Modification", "File Attribute Change"),
    "T1564.001": ("File Attribute Change", "File Modification", "Process Creation"),
    "T1552": ("File Access", "Sensitive File Read", "Process Creation"),
    "T1552.001": ("File Access", "Sensitive File Read", "Web Server Access Log"),
}

_COMPONENT_TO_LOGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Process Creation", ("Sysmon Event ID 1", "Windows Security 4688", "EDR process telemetry")),
    ("Command Execution", ("Sysmon Event ID 1 CommandLine", "EDR command-line telemetry")),
    ("Script Block Logging", ()),
    ("Module Load", ("Sysmon Event ID 7", "EDR module telemetry")),
    ("File Creation", ("Sysmon Event ID 11", "EDR file telemetry")),
    ("File Modification", ("Sysmon Event ID 11/15", "EDR file telemetry")),
    ("File Deletion", ("Sysmon Event ID 23/26", "EDR file telemetry")),
    ("File Access", ("EDR file telemetry", "Windows object access auditing when enabled")),
    ("Sensitive File Read", ("EDR file telemetry",)),
    ("Registry Key Modification", ("Sysmon Event ID 12/13/14", "Windows registry auditing")),
    ("Registry Value Modification", ("Sysmon Event ID 12/13/14",)),
    ("Registry Access", ("Sysmon Event ID 12/13/14", "EDR registry telemetry")),
    ("Network Connection", ("Sysmon Event ID 3", "EDR network telemetry")),
    ("Network Flow", ("Firewall traffic log", "NetFlow/IPFIX")),
    ("Connection Attempt", ("Firewall traffic log", "NetFlow/IPFIX")),
    ("Firewall Traffic", ("Firewall traffic log",)),
    ("DNS Query", ("Sysmon Event ID 22", "DNS server log", "DNS resolver log")),
    ("HTTP Request", ("NGINX/Apache/IIS access log", "Proxy log", "WAF log")),
    ("Web Server Access Log", ("NGINX/Apache/IIS access log",)),
    ("WAF/Security Alert", ("WAF/security log",)),
    ("HTTP File Upload", ("NGINX/Apache/IIS access log", "Application upload log", "WAF log")),
    ("Proxy Request", ("Proxy log", "Secure web gateway log")),
    ("Large Upload", ("Proxy log", "Firewall traffic log", "DLP alert")),
    ("Authentication Event", ("Windows Security 4624/4625", "Application auth log", "IdP sign-in log")),
    ("Logon Event", ("Windows Security 4624/4625/4648", "IdP sign-in log")),
    ("Logon Failure", ("Windows Security 4625", "Application auth log", "IdP sign-in log")),
    ("Logon Success", ("Windows Security 4624", "Application auth log", "IdP sign-in log")),
    ("Authentication Success", ("Windows Security 4624", "IdP sign-in log")),
    ("Account Context", ("Windows Security 4624/4672", "Identity provider user context")),
    ("Source IP/User Correlation", ("Windows Security 4625", "Application auth log", "IdP sign-in log")),
    ("Account Management", ("Windows Security 4720/4722/4732", "IdP audit log")),
    ("Service Creation", ("Windows System 7045", "Sysmon Event ID 6/7", "EDR service telemetry")),
    ("Service Modification", ("Windows System 7040/7045", "EDR service telemetry")),
    ("Remote Service Creation", ("Windows System 7045", "Windows Security 4624/4672")),
    ("Scheduled Task Event", ("Windows Security 4698/4702", "TaskScheduler Operational log")),
    ("Windows Security 4698", ("Windows Security 4698",)),
    ("Process Access", ("Sysmon Event ID 10", "EDR process access telemetry")),
    ("LSASS Access", ("Sysmon Event ID 10", "EDR credential access alert")),
    ("Credential Store Access", ("Sysmon Event ID 10/11", "EDR credential telemetry")),
    ("Memory Allocation", ("EDR memory telemetry",)),
    ("Token/Privilege Use", ("Windows Security 4672/4673/4674", "EDR privilege telemetry")),
    ("Exploit Telemetry", ()),
    ("Kernel/EDR Alert", ("EDR exploit alert",)),
    ("Cloud Audit Event", ("AWS CloudTrail", "Azure Activity/Audit logs", "Google Cloud Audit Logs")),
    ("Container Audit Event", ("Kubernetes audit log", "container runtime log")),
    ("WMI Activity", ("Windows WMI-Activity 5857/5861", "Sysmon Event ID 1")),
    ("Driver Load", ("Sysmon Event ID 6", "Windows CodeIntegrity log")),
    ("Kernel Object Access", ("Windows object access auditing", "EDR kernel telemetry")),
    ("File Attribute Change", ("Sysmon Event ID 1/11", "EDR file telemetry")),
    ("EDR Tamper Alert", ("EDR tamper telemetry",)),
)

_COMPONENT_GAPS: dict[str, str] = {
    "Script Block Logging": "Enable PowerShell Script Block Logging (Event ID 4104).",
    "Exploit Telemetry": "Add EDR exploit-prevention telemetry or application exploit logs.",
    "Kernel/EDR Alert": "Enable kernel/EDR exploit and privilege-escalation sensors.",
    "Token/Privilege Use": "Enable Windows privilege-use auditing and collect EDR token events.",
    "Sensitive File Read": "Enable file access auditing for sensitive paths or EDR file-read telemetry.",
    "Cloud Audit Event": "Connect cloud control-plane audit logs.",
    "Container Audit Event": "Collect Kubernetes/container runtime audit logs.",
}


def build_telemetry_readiness(
    attack_id: str,
    name: str,
    tactics: list[str],
    platforms: list[str],
    data_sources: list[str],
) -> TelemetryReadiness:
    required = _required_components(attack_id, tactics, platforms, data_sources)
    available_logs = _available_logs(required)
    missing = [component for component in required if not _logs_for_component(component)]
    gaps = [_gap_for(component) for component in missing]
    gaps.extend(_platform_gaps(platforms, required))
    score = _score(required, missing)
    feasibility = "High" if score >= 75 else "Medium" if score >= 45 else "Low"

    if attack_id == "T1059.001" and any("Script Block Logging" in component for component in missing):
        gaps.append(
            "Enable PowerShell Script Block Logging (Event ID 4104) to inspect script content, not only process command line."
        )
        score = min(score, 65)
        feasibility = "Medium"
    gaps = _dedupe(gaps)

    return TelemetryReadiness(
        required_data_components=required,
        available_logs=available_logs,
        missing_telemetry=missing,
        detection_feasibility=feasibility,
        readiness_score=score,
        gaps=gaps or ["No critical telemetry gap inferred from current ATT&CK data sources; validate local sensor coverage."],
    )


def infer_telemetry_source_tags(
    attack_id: str,
    tactics: list[str],
    platforms: list[str],
    data_sources: list[str],
    detection: str = "",
    description: str = "",
    name: str = "",
) -> list[str]:
    """Return stable source tags for a technique, even when ATT&CK has no data_sources list."""
    tags: list[str] = []
    for source in data_sources or []:
        normalized = _normalize_source_tag(source)
        if normalized:
            tags.append(normalized)

    required = _required_components(attack_id, tactics, platforms, data_sources or [])
    for component in required:
        tags.extend(_tags_for_component(component))

    text = " ".join([name, description, detection, " ".join(platforms), " ".join(tactics)]).lower()
    keyword_tags = (
        ("powershell", "powershell:script-block"),
        ("script", "script:execution"),
        ("command line", "command:execution"),
        ("process", "process:creation"),
        ("registry", "registry:modification"),
        ("file", "file:activity"),
        ("credential", "authentication:credential"),
        ("logon", "authentication:logon"),
        ("network", "network:connection"),
        ("dns", "dns:query"),
        ("http", "web:http"),
        ("web", "web:http"),
        ("proxy", "proxy:request"),
        ("cloud", "cloud:audit"),
        ("container", "container:audit"),
        ("service", "service:change"),
        ("scheduled task", "scheduled-task:event"),
        ("wmi", "wmi:activity"),
    )
    for token, tag in keyword_tags:
        if token in text:
            tags.append(tag)

    if not tags:
        tags.extend(("process:creation", "network:connection"))
    return _dedupe(tags)


def _normalize_source_tag(source: str) -> str:
    value = " ".join(str(source or "").replace("_", " ").split())
    if not value:
        return ""
    if ":" in value:
        family, component = value.split(":", 1)
        return f"{_source_family_slug(family)}:{_slug(component)}"
    return f"{_slug(value)}:attck"


def _tags_for_component(component: str) -> tuple[str, ...]:
    component_map: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("Process Creation", ("process:creation",)),
        ("Command Execution", ("command:execution",)),
        ("Script Block Logging", ("powershell:script-block", "script:execution")),
        ("Module Load", ("module:load",)),
        ("File Creation", ("file:creation",)),
        ("File Modification", ("file:modification",)),
        ("File Deletion", ("file:deletion",)),
        ("File Access", ("file:access",)),
        ("File Read", ("file:read",)),
        ("Sensitive File Read", ("file:sensitive-read",)),
        ("Registry Key Modification", ("registry:modification",)),
        ("Registry Value Modification", ("registry:modification",)),
        ("Registry Access", ("registry:access",)),
        ("Network Connection", ("network:connection",)),
        ("Network Flow", ("network:flow",)),
        ("Connection Attempt", ("network:connection-attempt",)),
        ("Firewall Traffic", ("firewall:traffic",)),
        ("DNS Query", ("dns:query",)),
        ("HTTP Request", ("web:http",)),
        ("Web Server Access Log", ("web:access-log",)),
        ("WAF/Security Alert", ("waf:alert",)),
        ("HTTP File Upload", ("web:file-upload",)),
        ("Proxy Request", ("proxy:request",)),
        ("Large Upload", ("network:large-upload", "proxy:upload")),
        ("Authentication Event", ("authentication:event",)),
        ("Logon Event", ("authentication:logon",)),
        ("Logon Failure", ("authentication:failure",)),
        ("Logon Success", ("authentication:success",)),
        ("Authentication Success", ("authentication:success",)),
        ("Account Context", ("identity:account-context",)),
        ("Source IP/User Correlation", ("identity:source-correlation",)),
        ("Account Management", ("identity:account-management",)),
        ("Service Creation", ("service:creation",)),
        ("Service Modification", ("service:modification",)),
        ("Remote Service Creation", ("service:remote-creation",)),
        ("Scheduled Task Event", ("scheduled-task:event",)),
        ("Windows Security 4698", ("windows-security:4698",)),
        ("Process Access", ("process:access",)),
        ("LSASS Access", ("edr:lsass-access",)),
        ("Credential Store Access", ("credential-store:access",)),
        ("Memory Allocation", ("memory:allocation",)),
        ("Token/Privilege Use", ("privilege:use",)),
        ("Exploit Telemetry", ("edr:exploit",)),
        ("Kernel/EDR Alert", ("edr:kernel-alert",)),
        ("Cloud Audit Event", ("cloud:audit",)),
        ("Container Audit Event", ("container:audit",)),
        ("WMI Activity", ("wmi:activity",)),
        ("Driver Load", ("driver:load",)),
        ("Kernel Object Access", ("kernel:object-access",)),
        ("File Attribute Change", ("file:attribute-change",)),
        ("EDR Tamper Alert", ("edr:tamper",)),
    )
    tags: list[str] = []
    for token, mapped in component_map:
        if token == component:
            tags.extend(mapped)
    if tags:
        return tuple(tags)
    lowered = component.lower()
    for token, mapped in component_map:
        if token.lower() in lowered:
            tags.extend(mapped)
    return tuple(tags)


def _slug(value: str) -> str:
    out = []
    previous_dash = False
    for char in value.strip().lower():
        if char.isalnum():
            out.append(char)
            previous_dash = False
        elif not previous_dash:
            out.append("-")
            previous_dash = True
    return "".join(out).strip("-")


def _source_family_slug(value: str) -> str:
    slug = _slug(value)
    aliases = {
        "wineventlog": "windows-event-log",
        "nsm": "network-security-monitoring",
        "sysmon": "windows-event-log",
        "windows-security": "windows-security",
        "windows-event-log": "windows-event-log",
    }
    return aliases.get(slug, slug)


def _required_components(attack_id: str, tactics: list[str], platforms: list[str], data_sources: list[str]) -> list[str]:
    components: list[str] = []
    if attack_id in _TECHNIQUE_OVERRIDES:
        components.extend(_TECHNIQUE_OVERRIDES[attack_id])
    elif "." in attack_id and attack_id.split(".", 1)[0] in _TECHNIQUE_OVERRIDES:
        components.extend(_TECHNIQUE_OVERRIDES[attack_id.split(".", 1)[0]])

    for source in data_sources:
        lowered = source.lower()
        for token, mapped in _SOURCE_TO_COMPONENTS:
            if token in lowered:
                components.extend(mapped)

    for tactic in tactics:
        components.extend(_TACTIC_COMPONENTS.get(tactic, ()))

    platform_text = " ".join(platforms).lower()
    if "windows" in platform_text:
        components.extend(("Process Creation", "Windows Event Log"))
    if "linux" in platform_text or "macos" in platform_text:
        components.extend(("Process Creation", "Auditd/Endpoint Telemetry"))
    if "network" in platform_text:
        components.extend(("Network Flow",))
    if not components:
        components.extend(("Process Creation", "Network Connection"))

    return _dedupe([component for component in components if component != "Windows Event Log" and component != "Auditd/Endpoint Telemetry"])


def _available_logs(required: list[str]) -> list[str]:
    logs: list[str] = []
    for component in required:
        logs.extend(_logs_for_component(component))
    return _dedupe(logs)


def _logs_for_component(component: str) -> tuple[str, ...]:
    for token, logs in _COMPONENT_TO_LOGS:
        if token == component:
            return logs
    return ()


def _score(required: list[str], missing: list[str]) -> int:
    if not required:
        return 0
    covered = len(required) - len(missing)
    return max(0, min(100, round((covered / len(required)) * 100)))


def _gap_for(component: str) -> str:
    return _COMPONENT_GAPS.get(component, f"Collect and normalize {component} telemetry.")


def _platform_gaps(platforms: list[str], required: list[str]) -> list[str]:
    text = " ".join(platforms).lower()
    gaps: list[str] = []
    if "windows" in text and "Process Creation" in required:
        gaps.append("Confirm Sysmon Event ID 1 or Windows Security 4688 is collected with command line.")
    if "linux" in text:
        gaps.append("Confirm auditd/eBPF/EDR process and file telemetry is collected for Linux hosts.")
    if "cloud" in text:
        gaps.append("Confirm cloud audit logs are connected to the SIEM with identity and source IP fields.")
    return gaps


def _dedupe(values: list[str] | tuple[str, ...]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
