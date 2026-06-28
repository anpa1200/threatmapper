from __future__ import annotations

import json
import re
from typing import Any


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def atomic_simulation_id(spec: dict[str, Any]) -> str:
    return f"sim-{spec['technique_id'].lower().replace('.', '-')}-atomic-{_slug(spec['slug'])}"


def atomic_category(spec: dict[str, Any]) -> str:
    return f"atomic_{spec['technique_id'].lower().replace('.', '_')}_{_slug(spec['slug']).replace('-', '_')}"


def build_atomic_event_requests() -> dict[str, list[dict[str, Any]]]:
    requests: dict[str, list[dict[str, Any]]] = {}
    for spec in ATOMIC_EVENT_SPECS:
        event = {
            **spec["event"],
            "ag_canary": atomic_category(spec),
            "operation": spec.get("operation", "atomic_event_artifact"),
        }
        requests[atomic_simulation_id(spec)] = [
            {
                "method": "POST",
                "path": "/endpoint/activity",
                "body": json.dumps(event, sort_keys=True),
                "purpose": f"{spec['technique_id']} atomic event: {spec['name']}",
            }
        ]
    return requests


ATOMIC_EVENT_SPECS: list[dict[str, Any]] = [
    {
        "technique_id": "T1027",
        "slug": "encoded-powershell-scriptblock",
        "name": "Obfuscated PowerShell script block",
        "event": {"provider": "windows_powershell", "event_id": "4104", "event_name": "ScriptBlockLogging", "severity": "high", "process": "powershell.exe", "command": "IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgA')))", "rule_name": "Encoded PowerShell script block", "source_vendor": "Microsoft", "source_product": "PowerShell"},
    },
    {
        "technique_id": "T1036",
        "slug": "masqueraded-svchost-user-path",
        "name": "Masqueraded system process from user-writable path",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "high", "process": "svchost.exe", "command": "C:\\Users\\Public\\svchost.exe -k netsvcs", "file_path": "C:\\Users\\Public\\svchost.exe", "parent_process": "explorer.exe", "rule_name": "System binary name outside system directory"},
    },
    {
        "technique_id": "T1047",
        "slug": "wmic-process-call-create",
        "name": "WMI process creation",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "wmic.exe", "command": "wmic process call create \"cmd.exe /c whoami\"", "parent_process": "cmd.exe", "rule_name": "WMIC process call create"},
    },
    {
        "technique_id": "T1049",
        "slug": "netstat-network-connections",
        "name": "System network connection discovery",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "netstat.exe", "command": "netstat.exe -ano", "parent_process": "cmd.exe", "rule_name": "Network connection discovery command"},
    },
    {
        "technique_id": "T1055",
        "slug": "remote-thread-injection",
        "name": "Remote thread creation into another process",
        "event": {"provider": "sysmon", "event_id": "8", "event_name": "CreateRemoteThread", "severity": "high", "process": "rundll32.exe", "target_process": "explorer.exe", "source_image": "C:\\Windows\\System32\\rundll32.exe", "target_image": "C:\\Windows\\explorer.exe", "rule_name": "Remote thread injection"},
    },
    {
        "technique_id": "T1056.001",
        "slug": "keylogger-driver-or-hook",
        "name": "Keylogging hook artifact",
        "event": {"provider": "edr", "event_id": "INPUT_CAPTURE", "event_name": "KeyboardHookRegistered", "severity": "high", "process": "ag-input.exe", "command": "SetWindowsHookEx WH_KEYBOARD_LL", "operation": "keyboard_hook", "rule_name": "Low-level keyboard hook"},
    },
    {
        "technique_id": "T1068",
        "slug": "privilege-escalation-exploit-child-shell",
        "name": "Privileged service spawned shell after exploit-like event",
        "event": {"provider": "edr", "event_id": "PRIV_ESC", "event_name": "ExploitPrivilegeEscalation", "severity": "high", "process": "cmd.exe", "parent_process": "spoolsv.exe", "command": "cmd.exe /c whoami", "rule_name": "Service spawned interactive shell"},
    },
    {
        "technique_id": "T1070.001",
        "slug": "windows-event-log-cleared",
        "name": "Windows event log cleared",
        "event": {"provider": "windows_security", "event_id": "1102", "event_name": "AuditLogCleared", "severity": "high", "process": "wevtutil.exe", "command": "wevtutil cl Security", "object": "Security", "rule_name": "Security log cleared"},
    },
    {
        "technique_id": "T1070.004",
        "slug": "suspicious-file-delete",
        "name": "Suspicious file deletion",
        "event": {"provider": "sysmon", "event_id": "23", "event_name": "FileDelete", "severity": "medium", "process": "cmd.exe", "command": "del /f /q C:\\Users\\Public\\stage.exe", "file_path": "C:\\Users\\Public\\stage.exe", "rule_name": "Suspicious staged file deletion"},
    },
    {
        "technique_id": "T1078",
        "slug": "valid-account-remote-logon",
        "name": "Valid account remote interactive logon",
        "event": {"provider": "windows_security", "event_id": "4624", "event_name": "SuccessfulLogon", "severity": "medium", "target_user": "lab-admin", "logon_type": "10", "src_ip": "10.10.20.55", "process": "winlogon.exe", "rule_name": "Remote interactive logon by privileged user"},
    },
    {
        "technique_id": "T1098",
        "slug": "account-added-to-admin-group",
        "name": "Account added to privileged group",
        "event": {"provider": "windows_security", "event_id": "4728", "event_name": "MemberAddedToSecurityEnabledGlobalGroup", "severity": "high", "target_user": "svc-backup", "object": "Domain Admins", "process": "net.exe", "command": "net group \"Domain Admins\" svc-backup /add /domain", "rule_name": "Privileged group membership changed"},
    },
    {
        "technique_id": "T1102",
        "slug": "web-service-c2-user-agent",
        "name": "Web service used as C2 channel",
        "event": {"provider": "proxy", "event_id": "HTTP_REQUEST", "event_name": "ProxyWebRequest", "severity": "medium", "process": "powershell.exe", "url": "https://paste.example.test/raw/ag-canary", "destination_domain": "paste.example.test", "user_agent": "Mozilla/5.0 PowerShell", "rule_name": "Suspicious web service callback"},
    },
    {
        "technique_id": "T1106",
        "slug": "suspicious-native-api-call",
        "name": "Suspicious Native API sequence",
        "event": {"provider": "edr", "event_id": "API_CALL", "event_name": "NativeApiCall", "severity": "medium", "process": "ag-loader.exe", "api": "VirtualAllocEx,WriteProcessMemory,CreateRemoteThread", "target_process": "notepad.exe", "rule_name": "Process injection API sequence"},
    },
    {
        "technique_id": "T1112",
        "slug": "registry-security-setting-modified",
        "name": "Security-sensitive registry modification",
        "event": {"provider": "sysmon", "event_id": "13", "event_name": "RegistryValueSet", "severity": "high", "process": "reg.exe", "command": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f", "registry_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA", "rule_name": "UAC policy disabled"},
    },
    {
        "technique_id": "T1113",
        "slug": "screen-capture-api",
        "name": "Screen capture API use",
        "event": {"provider": "edr", "event_id": "SCREEN_CAPTURE", "event_name": "ScreenCapture", "severity": "medium", "process": "ag-viewer.exe", "api": "BitBlt,GetDC", "file_path": "C:\\Users\\Public\\screen.png", "rule_name": "Screen capture artifact"},
    },
    {
        "technique_id": "T1115",
        "slug": "clipboard-read",
        "name": "Clipboard data access",
        "event": {"provider": "edr", "event_id": "CLIPBOARD_READ", "event_name": "ClipboardAccess", "severity": "medium", "process": "ag-viewer.exe", "api": "OpenClipboard,GetClipboardData", "rule_name": "Clipboard collection"},
    },
    {
        "technique_id": "T1123",
        "slug": "audio-capture-api",
        "name": "Audio capture API use",
        "event": {"provider": "edr", "event_id": "AUDIO_CAPTURE", "event_name": "MicrophoneAccess", "severity": "medium", "process": "ag-recorder.exe", "api": "waveInOpen", "rule_name": "Microphone capture"},
    },
    {
        "technique_id": "T1125",
        "slug": "video-capture-api",
        "name": "Video capture API use",
        "event": {"provider": "edr", "event_id": "VIDEO_CAPTURE", "event_name": "CameraAccess", "severity": "medium", "process": "ag-recorder.exe", "api": "capCreateCaptureWindow", "rule_name": "Camera capture"},
    },
    {
        "technique_id": "T1134",
        "slug": "token-impersonation",
        "name": "Access token impersonation",
        "event": {"provider": "edr", "event_id": "TOKEN_IMPERSONATION", "event_name": "TokenImpersonation", "severity": "high", "process": "ag-loader.exe", "target_user": "NT AUTHORITY\\SYSTEM", "api": "DuplicateTokenEx,ImpersonateLoggedOnUser", "rule_name": "Token impersonation"},
    },
    {
        "technique_id": "T1135",
        "slug": "network-share-discovery",
        "name": "Network share discovery",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "net.exe", "command": "net view \\\\fileserver01 /all", "share_name": "\\\\fileserver01", "rule_name": "Network share discovery command"},
    },
    {
        "technique_id": "T1140",
        "slug": "certutil-decode",
        "name": "File deobfuscation with certutil decode",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "high", "process": "certutil.exe", "command": "certutil.exe -decode C:\\Users\\Public\\payload.b64 C:\\Users\\Public\\payload.exe", "rule_name": "Certutil decode"},
    },
    {
        "technique_id": "T1203",
        "slug": "office-spawned-script-host",
        "name": "Exploitation for client execution artifact",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "high", "process": "wscript.exe", "parent_process": "WINWORD.EXE", "command": "wscript.exe C:\\Users\\Public\\invoice.js", "rule_name": "Office spawned script host"},
    },
    {
        "technique_id": "T1204.002",
        "slug": "user-executed-downloaded-file",
        "name": "User execution of downloaded file",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "invoice.exe", "file_path": "C:\\Users\\lab\\Downloads\\invoice.exe", "parent_process": "explorer.exe", "file_hash": "SHA256=2f3f6b6d8a8b9c0d1e2f3a4b5c6d7e8f90123456789abcdef0123456789abcd", "rule_name": "Downloaded executable launched"},
    },
    {
        "technique_id": "T1219",
        "slug": "remote-access-software-started",
        "name": "Remote access software execution",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "AnyDesk.exe", "command": "AnyDesk.exe --service", "destination_domain": "relay.anydesk.com", "rule_name": "Remote access software started"},
    },
    {
        "technique_id": "T1222.001",
        "slug": "icacls-permission-change",
        "name": "Windows file permission modification",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "icacls.exe", "command": "icacls C:\\Users\\Public\\stage.exe /grant Everyone:F", "file_path": "C:\\Users\\Public\\stage.exe", "rule_name": "Suspicious ACL modification"},
    },
    {
        "technique_id": "T1482",
        "slug": "domain-trust-discovery",
        "name": "Domain trust discovery",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "nltest.exe", "command": "nltest /domain_trusts", "rule_name": "Domain trust discovery command"},
    },
    {
        "technique_id": "T1486",
        "slug": "ransomware-file-rename",
        "name": "Ransomware-like file encryption artifact",
        "event": {"provider": "edr", "event_id": "RANSOMWARE_CANARY", "event_name": "MassFileRename", "severity": "critical", "process": "ag-crypt.exe", "file_path": "C:\\Shares\\Finance\\report.xlsx.aglocked", "operation": "file_rename", "rule_name": "Ransomware extension canary"},
    },
    {
        "technique_id": "T1490",
        "slug": "shadow-copy-deletion",
        "name": "Inhibit system recovery command",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "critical", "process": "vssadmin.exe", "command": "vssadmin.exe delete shadows /all /quiet", "rule_name": "Shadow copy deletion"},
    },
    {
        "technique_id": "T1497",
        "slug": "sandbox-evasion-check",
        "name": "Virtualization and sandbox evasion check",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "wmic.exe", "command": "wmic computersystem get manufacturer,model", "rule_name": "VM/sandbox discovery command"},
    },
    {
        "technique_id": "T1518.001",
        "slug": "security-software-discovery",
        "name": "Security software discovery",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "powershell.exe", "command": "Get-Process MsMpEng,SentinelAgent,CrowdStrike", "rule_name": "Security product discovery"},
    },
    {
        "technique_id": "T1539",
        "slug": "browser-cookie-access",
        "name": "Browser cookie database access",
        "event": {"provider": "sysmon", "event_id": "11", "event_name": "FileCreate", "severity": "high", "process": "powershell.exe", "file_path": "C:\\Users\\lab\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", "operation": "file_read", "rule_name": "Browser cookie store access"},
    },
    {
        "technique_id": "T1546.003",
        "slug": "wmi-event-subscription",
        "name": "WMI event subscription persistence",
        "event": {"provider": "sysmon", "event_id": "19", "event_name": "WmiEventFilter", "severity": "high", "process": "powershell.exe", "command": "Set-WmiInstance -Namespace root\\subscription -Class __EventFilter", "rule_name": "WMI event subscription created"},
    },
    {
        "technique_id": "T1546.008",
        "slug": "accessibility-feature-backdoor",
        "name": "Accessibility feature persistence",
        "event": {"provider": "sysmon", "event_id": "13", "event_name": "RegistryValueSet", "severity": "high", "process": "reg.exe", "registry_key": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger", "rule_name": "Accessibility debugger persistence"},
    },
    {
        "technique_id": "T1547.009",
        "slug": "shortcut-modification",
        "name": "Shortcut modification persistence",
        "event": {"provider": "sysmon", "event_id": "11", "event_name": "FileCreate", "severity": "medium", "process": "powershell.exe", "file_path": "C:\\Users\\lab\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\OneDrive.lnk", "rule_name": "Startup shortcut created"},
    },
    {
        "technique_id": "T1550.002",
        "slug": "pass-the-hash-logon",
        "name": "Pass-the-Hash style network logon",
        "event": {"provider": "windows_security", "event_id": "4624", "event_name": "SuccessfulLogon", "severity": "high", "target_user": "lab-admin", "logon_type": "3", "src_ip": "10.10.20.77", "authentication_package": "NTLM", "rule_name": "NTLM network logon from unusual host"},
    },
    {
        "technique_id": "T1552.002",
        "slug": "credentials-in-registry",
        "name": "Credentials read from registry",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "high", "process": "reg.exe", "command": "reg query HKLM\\SECURITY\\Policy\\Secrets", "registry_key": "HKLM\\SECURITY\\Policy\\Secrets", "rule_name": "Registry secret query"},
    },
    {
        "technique_id": "T1552.006",
        "slug": "cloud-credential-file-access",
        "name": "Cloud credential file access",
        "event": {"provider": "edr", "event_id": "FILE_READ", "event_name": "SensitiveFileAccess", "severity": "high", "process": "python.exe", "file_path": "C:\\Users\\lab\\.aws\\credentials", "rule_name": "Cloud credential file access"},
    },
    {
        "technique_id": "T1555.003",
        "slug": "browser-login-data-access",
        "name": "Browser credential store access",
        "event": {"provider": "sysmon", "event_id": "11", "event_name": "FileCreate", "severity": "high", "process": "powershell.exe", "file_path": "C:\\Users\\lab\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "rule_name": "Browser login database access"},
    },
    {
        "technique_id": "T1556.002",
        "slug": "password-filter-dll-registered",
        "name": "Password filter DLL registration",
        "event": {"provider": "sysmon", "event_id": "13", "event_name": "RegistryValueSet", "severity": "critical", "process": "reg.exe", "registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages", "file_path": "C:\\Windows\\System32\\agpassflt.dll", "rule_name": "Password filter registered"},
    },
    {
        "technique_id": "T1560.001",
        "slug": "archive-with-rar",
        "name": "Archive collected data with utility",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "rar.exe", "command": "rar.exe a -hpSecret C:\\Users\\Public\\stage.rar C:\\Users\\Public\\*.docx", "file_path": "C:\\Users\\Public\\stage.rar", "rule_name": "Password-protected archive creation"},
    },
    {
        "technique_id": "T1562.001",
        "slug": "disable-defender-realtime",
        "name": "Impair defenses by disabling Defender",
        "event": {"provider": "windows_defender", "event_id": "5007", "event_name": "ConfigurationChanged", "severity": "critical", "process": "powershell.exe", "command": "Set-MpPreference -DisableRealtimeMonitoring $true", "rule_name": "Defender real-time monitoring disabled"},
    },
    {
        "technique_id": "T1562.004",
        "slug": "disable-windows-firewall",
        "name": "Disable host firewall",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "high", "process": "netsh.exe", "command": "netsh advfirewall set allprofiles state off", "rule_name": "Windows firewall disabled"},
    },
    {
        "technique_id": "T1564.001",
        "slug": "hidden-file-attribute",
        "name": "Hidden file attribute set",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "attrib.exe", "command": "attrib +h +s C:\\Users\\Public\\stage.exe", "file_path": "C:\\Users\\Public\\stage.exe", "rule_name": "Hidden/system attribute on staged file"},
    },
    {
        "technique_id": "T1566.001",
        "slug": "email-attachment-delivery",
        "name": "Spearphishing attachment delivery",
        "event": {"provider": "email_gateway", "event_id": "MESSAGE_DELIVERED", "event_name": "EmailDelivered", "severity": "medium", "source_product": "SecureEmailGateway", "file_name": "invoice.docm", "file_hash": "SHA256=91b0f0bda1f2b6e9f676abc0123456789abcdef0123456789abcdef012345678", "target_user": "analyst@example.test", "rule_name": "Macro-enabled attachment delivered"},
    },
    {
        "technique_id": "T1567.002",
        "slug": "exfil-to-cloud-storage",
        "name": "Exfiltration to cloud storage",
        "event": {"provider": "proxy", "event_id": "HTTP_UPLOAD", "event_name": "LargeUpload", "severity": "high", "process": "rclone.exe", "url": "https://storage.googleapis.com/upload/storage/v1/b/ag-canary/o", "destination_domain": "storage.googleapis.com", "bytes_out": "52428800", "rule_name": "Large upload to cloud storage"},
    },
    {
        "technique_id": "T1569.002",
        "slug": "service-execution",
        "name": "Service execution",
        "event": {"provider": "windows_system", "event_id": "7045", "event_name": "ServiceInstalled", "severity": "high", "process": "services.exe", "service_name": "AGCanarySvc", "file_path": "C:\\Users\\Public\\ag.exe", "rule_name": "Service installed for execution"},
    },
    {
        "technique_id": "T1574.002",
        "slug": "dll-side-loading",
        "name": "DLL side-loading artifact",
        "event": {"provider": "sysmon", "event_id": "7", "event_name": "ImageLoaded", "severity": "high", "process": "signed-app.exe", "file_path": "C:\\Users\\Public\\version.dll", "signature": "Unsigned", "rule_name": "Unsigned DLL loaded by signed process"},
    },
    {
        "technique_id": "T1574.011",
        "slug": "services-registry-permissions-weakness",
        "name": "Service registry permissions weakness artifact",
        "event": {"provider": "sysmon", "event_id": "13", "event_name": "RegistryValueSet", "severity": "high", "process": "reg.exe", "registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WeakSvc\\ImagePath", "file_path": "C:\\Users\\Public\\ag.exe", "rule_name": "Service ImagePath modified"},
    },
    {
        "technique_id": "T1021.001",
        "slug": "rdp-network-logon",
        "name": "Remote Desktop Protocol logon",
        "event": {"provider": "windows_security", "event_id": "4624", "event_name": "SuccessfulLogon", "severity": "medium", "target_user": "lab-admin", "logon_type": "10", "src_ip": "10.10.30.44", "dest_port": "3389", "protocol": "RDP", "rule_name": "RDP logon"},
    },
    {
        "technique_id": "T1021.002",
        "slug": "smb-admin-share-access",
        "name": "SMB admin share access",
        "event": {"provider": "windows_security", "event_id": "5140", "event_name": "NetworkShareAccess", "severity": "medium", "target_user": "lab-admin", "share_name": "\\\\*\\ADMIN$", "src_ip": "10.10.30.45", "protocol": "SMB", "rule_name": "Administrative share accessed"},
    },
    {
        "technique_id": "T1039",
        "slug": "network-share-data-access",
        "name": "Data from network shared drive",
        "event": {"provider": "windows_security", "event_id": "4663", "event_name": "ObjectAccess", "severity": "medium", "process": "robocopy.exe", "object_path": "\\\\fileserver01\\finance\\payroll.xlsx", "share_name": "\\\\fileserver01\\finance", "rule_name": "Sensitive file accessed on network share"},
    },
    {
        "technique_id": "T1059.005",
        "slug": "visual-basic-script-execution",
        "name": "Visual Basic script execution",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "wscript.exe", "command": "wscript.exe C:\\Users\\Public\\update.vbs", "parent_process": "explorer.exe", "rule_name": "VBScript execution"},
    },
    {
        "technique_id": "T1059.006",
        "slug": "python-execution",
        "name": "Python script execution",
        "event": {"provider": "sysmon", "event_id": "1", "event_name": "ProcessCreate", "severity": "medium", "process": "python.exe", "command": "python.exe C:\\Users\\Public\\stage.py", "parent_process": "cmd.exe", "rule_name": "Python execution from user-writable path"},
    },
    {
        "technique_id": "T1090",
        "slug": "proxy-tool-network-connection",
        "name": "Proxy tool network connection",
        "event": {"provider": "sysmon", "event_id": "3", "event_name": "NetworkConnection", "severity": "medium", "process": "chisel.exe", "destination_ip": "203.0.113.20", "destination_port": "443", "destination_domain": "relay.example.test", "rule_name": "Proxy/tunnel tool outbound connection"},
    },
    {
        "technique_id": "T1048",
        "slug": "exfiltration-over-alternative-protocol",
        "name": "Exfiltration over alternative protocol",
        "event": {"provider": "firewall", "event_id": "NETFLOW", "event_name": "OutboundTransfer", "severity": "high", "process": "rclone.exe", "destination_ip": "203.0.113.55", "destination_port": "22", "protocol": "SFTP", "bytes_out": "73400320", "rule_name": "Large outbound transfer over SFTP"},
    },
]


ATOMIC_EVENT_SIMULATION_IDS = {atomic_simulation_id(spec) for spec in ATOMIC_EVENT_SPECS}
ATOMIC_EVENT_CATEGORIES = {atomic_category(spec) for spec in ATOMIC_EVENT_SPECS}
