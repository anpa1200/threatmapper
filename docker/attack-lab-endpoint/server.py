from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
from urllib import parse
from xml.sax.saxutils import escape


HOST = os.environ.get("ATTACK_LAB_ENDPOINT_HOST", "0.0.0.0")
PORT = int(os.environ.get("ATTACK_LAB_ENDPOINT_PORT", "8090"))
LOG_DIR = Path(os.environ.get("ATTACK_LAB_ENDPOINT_LOG_DIR", "/app/logs")) / "attack-simulation"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class EndpointLabHandler(BaseHTTPRequestHandler):
    server_version = "AdversaryGraphAttackLabEndpoint/1.0"

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def log_message(self, *_args) -> None:
        return

    def _handle_request(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._respond(200, b"ok\n", "text/plain; charset=utf-8")
            return
        if path != "/endpoint/activity":
            self._respond(404, b"not found\n", "text/plain; charset=utf-8")
            return
        request_body = self._read_request_body()
        event = self._endpoint_event(request_body)
        _append_jsonl(_endpoint_jsonl_path(), event)
        for category in _endpoint_categories(event):
            _append_text_line(_endpoint_log_path(), _format_endpoint_line(event, category))
        self._respond(200, b'{"status":"recorded","lab":"attack-simulation","target":"endpoint"}\n', "application/json")

    def _read_request_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        return self.rfile.read(min(length, 8192))

    def _respond(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-AdversaryGraph-Lab", "attack-simulation-endpoint")
        self.end_headers()
        self.wfile.write(payload)

    def _endpoint_event(self, request_body: bytes) -> dict[str, object]:
        headers = {key: value for key, value in self.headers.items()}
        header_lookup = {key.lower(): value for key, value in headers.items()}
        body_text = request_body.decode("utf-8", errors="replace")
        fields = _parse_body_fields(body_text)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "lab_endpoint_activity",
            "run_id": header_lookup.get("x-adversarygraph-run-id", ""),
            "simulation_id": header_lookup.get("x-adversarygraph-simulation-id", ""),
            "request_index": header_lookup.get("x-adversarygraph-request-index", ""),
            "client_ip": _client_ip_from_headers(header_lookup, self.client_address[0]),
            "method": self.command,
            "path": self.path,
            "process": fields.get("process", ""),
            "command": fields.get("command", ""),
            "args": fields.get("args", []),
            "file_path": fields.get("file_path", ""),
            "target_process": fields.get("target_process", ""),
            "operation": fields.get("operation", ""),
            "ag_canary": fields.get("ag_canary", ""),
            "provider": fields.get("provider", ""),
            "event_id": fields.get("event_id", ""),
            "event_name": fields.get("event_name", ""),
            "severity": fields.get("severity", ""),
            "host": fields.get("host", ""),
            "user": fields.get("user", ""),
            "parent_process": fields.get("parent_process", ""),
            "parent_command": fields.get("parent_command", ""),
            "registry_key": fields.get("registry_key", ""),
            "destination_ip": fields.get("destination_ip", ""),
            "destination_port": fields.get("destination_port", ""),
            "destination_domain": fields.get("destination_domain", ""),
            "url": fields.get("url", ""),
            "source_vendor": fields.get("source_vendor", ""),
            "source_product": fields.get("source_product", ""),
            "fields": fields,
            "body_length": len(request_body),
            "body_sha256": hashlib.sha256(request_body).hexdigest() if request_body else "",
        }
        return event


def _parse_body_fields(body: str) -> dict[str, object]:
    try:
        loaded = json.loads(body)
    except json.JSONDecodeError:
        return {key: values[-1] if values else "" for key, values in parse.parse_qs(body).items()}
    return loaded if isinstance(loaded, dict) else {}


def _client_ip_from_headers(headers: dict[str, str], fallback: str) -> str:
    forwarded_for = str(headers.get("x-forwarded-for") or "").split(",", 1)[0].strip()
    if forwarded_for:
        return forwarded_for
    real_ip = str(headers.get("x-real-ip") or "").strip()
    return real_ip or fallback


def _endpoint_categories(event: dict[str, object]) -> list[str]:
    canary = str(event.get("ag_canary") or "").lower()
    if canary.startswith("atomic_"):
        return [canary]
    if canary == "shadow_file_access":
        return ["shadow_file_access"]
    if canary == "mimikatz_lsass":
        return ["mimikatz_lsass"]
    if canary in {"lsass_minidump", "procdump_lsass"}:
        return ["lsass_dump"]
    if canary in {
        "powershell_encoded",
        "cmd_shell",
        "certutil_transfer",
        "run_key_persistence",
        "scheduled_task",
        "service_creation",
        "rundll32_proxy",
        "regsvr32_proxy",
        "system_discovery",
        "file_discovery",
        "user_discovery",
        "process_discovery",
        "network_config_discovery",
        "remote_system_discovery",
        "software_discovery",
    }:
        return [canary]
    return ["endpoint_activity"]


def _format_endpoint_line(event: dict[str, object], category: str) -> str:
    provider, event_id, event_name = _endpoint_provider_fields(category)
    provider = str(event.get("provider") or provider)
    event_id = str(event.get("event_id") or event_id)
    event_name = str(event.get("event_name") or event_name)
    if category.startswith("atomic_"):
        if _is_windows_event_provider(provider):
            return json.dumps(_windows_event_record(event, category, provider, event_id, event_name), sort_keys=True)
        return json.dumps(_vendor_event_record(event, category, provider, event_id, event_name), sort_keys=True)
    command = str(event.get("command") or " ".join(str(item) for item in event.get("args") or []) or "-")
    process = str(event.get("process") or _process_for_category(category))
    file_path = str(event.get("file_path") or _file_for_category(category) or "-")
    target_process = str(event.get("target_process") or "-")
    severity = str(event.get("severity") or _severity(category))
    host = str(event.get("host") or "attack-lab-endpoint")
    user = str(event.get("user") or "lab-user")
    fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
    extra_keys = [
        "parent_process",
        "parent_command",
        "registry_key",
        "destination_ip",
        "destination_port",
        "destination_domain",
        "url",
        "source_vendor",
        "source_product",
        "source_image",
        "target_image",
        "object",
        "object_path",
        "image",
        "parent_image",
        "target_user",
        "logon_type",
        "api",
        "event_source",
        "rule_name",
        "signature",
        "file_hash",
        "file_name",
        "share_name",
        "query_name",
        "query_type",
        "answer",
        "action",
        "result",
        "user_agent",
        "src_ip",
        "dest_ip",
        "dest_port",
        "bytes_out",
        "bytes_in",
        "protocol",
        "authentication_package",
        "service_name",
        "task_name",
        "mitre_tactic",
    ]
    extras = []
    for key in extra_keys:
        value = fields.get(key, event.get(key))
        if value not in (None, "", [], {}):
            extras.append(f'{key}="{_quote(value)}"')
    return (
        f'{event.get("timestamp") or datetime.now(timezone.utc).isoformat()} attack-simulation-endpoint '
        f'provider="{_quote(provider)}" event_id="{_quote(event_id)}" event_name="{_quote(event_name)}" '
        f'event="internal_activity" category="{_quote(category)}" severity="{_quote(severity)}" '
        f'host="{_quote(host)}" user="{_quote(user)}" process="{_quote(process)}" command="{_quote(command)}" '
        f'file_path="{_quote(file_path)}" target_process="{_quote(target_process)}" operation="{_quote(event.get("operation") or category)}" '
        f'client="{event.get("client_ip") or "-"}" method="{event.get("method") or "-"}" uri="{event.get("path") or "-"}" '
        f'status=200 run_id="{event.get("run_id") or "-"}" simulation_id="{event.get("simulation_id") or "-"}" '
        f'{" ".join(extras)} msg="Matched AdversaryGraph atomic endpoint canary: {_quote(category)}"'
    )


def _quote(value: object) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    return str(value).replace("\\", "\\\\").replace('"', r"\"")


def _is_windows_event_provider(provider: str) -> bool:
    normalized = provider.lower()
    return normalized in {
        "sysmon",
        "windows_security",
        "windows_system",
        "windows_defender",
        "windows_powershell",
    }


def _windows_event_record(
    event: dict[str, object],
    category: str,
    provider: str,
    event_id: str,
    event_name: str,
) -> dict[str, object]:
    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
    fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
    provider_name, provider_guid, channel = _windows_provider_identity(provider)
    computer = str(fields.get("computer") or event.get("host") or "AG-WIN-LAB01.adversarygraph.local")
    data = _windows_event_data(provider, event_id, fields, event)
    event_record = {
        "Event": {
            "System": {
                "Provider": {"Name": provider_name, "Guid": provider_guid},
                "EventID": int(event_id) if str(event_id).isdigit() else event_id,
                "Version": _windows_event_version(provider, event_id),
                "Level": _windows_level(str(event.get("severity") or fields.get("severity") or "medium")),
                "Task": _windows_task(provider, event_id),
                "Opcode": 0,
                "Keywords": _windows_keywords(provider),
                "TimeCreated": {"SystemTime": timestamp},
                "EventRecordID": _stable_event_record_id(event),
                "Correlation": {"ActivityID": f"{{{str(event.get('run_id') or 'run-00000000-0000-0000-0000-000000000000').replace('run-', '')}}}"},
                "Execution": {"ProcessID": 4 if provider == "windows_security" else 4242, "ThreadID": 1337},
                "Channel": channel,
                "Computer": computer,
                "Security": {"UserID": _security_sid(fields, event)},
            },
            "EventData": {"Data": [{"Name": key, "#text": str(value)} for key, value in data.items()]},
        },
        "winlog": {
            "provider_name": provider_name,
            "provider_guid": provider_guid,
            "channel": channel,
            "event_id": int(event_id) if str(event_id).isdigit() else event_id,
            "computer_name": computer,
            "record_id": _stable_event_record_id(event),
            "event_data": data,
        },
        "event": {
            "kind": "event",
            "category": _ecs_category(provider, event_id),
            "type": _ecs_type(provider, event_id),
            "provider": provider_name,
            "code": str(event_id),
            "action": event_name,
            "severity": str(event.get("severity") or fields.get("severity") or "medium"),
            "original": _windows_event_xml(provider_name, provider_guid, channel, computer, timestamp, event_id, data),
        },
        "adversarygraph": {
            "module": "Attack Simulation",
            "simulation_id": event.get("simulation_id") or "",
            "run_id": event.get("run_id") or "",
            "atomic_category": category,
            "note": "Windows Event Log shaped atomic validation fixture; no OS action was executed.",
        },
    }
    return event_record


def _windows_provider_identity(provider: str) -> tuple[str, str, str]:
    return {
        "sysmon": (
            "Microsoft-Windows-Sysmon",
            "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
            "Microsoft-Windows-Sysmon/Operational",
        ),
        "windows_security": (
            "Microsoft-Windows-Security-Auditing",
            "{54849625-5478-4994-A5BA-3E3B0328C30D}",
            "Security",
        ),
        "windows_system": (
            "Service Control Manager",
            "{555908D1-A6D7-4695-8E1E-26931D2012F4}",
            "System",
        ),
        "windows_defender": (
            "Microsoft-Windows-Windows Defender",
            "{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}",
            "Microsoft-Windows-Windows Defender/Operational",
        ),
        "windows_powershell": (
            "Microsoft-Windows-PowerShell",
            "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
            "Microsoft-Windows-PowerShell/Operational",
        ),
    }.get(provider, ("Microsoft-Windows-Sysmon", "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", "Microsoft-Windows-Sysmon/Operational"))


def _windows_event_data(provider: str, event_id: str, fields: dict[str, object], event: dict[str, object]) -> dict[str, object]:
    process = str(fields.get("process") or event.get("process") or "C:\\Windows\\System32\\cmd.exe")
    command = str(fields.get("command") or event.get("command") or process)
    file_path = str(fields.get("file_path") or event.get("file_path") or process)
    parent = str(fields.get("parent_process") or event.get("parent_process") or "C:\\Windows\\explorer.exe")
    user = str(fields.get("user") or event.get("user") or "AGLAB\\lab-user")
    sid = _security_sid(fields, event)
    base = {
        "RuleName": str(fields.get("rule_name") or "-"),
        "UtcTime": str(event.get("timestamp") or datetime.now(timezone.utc).isoformat()).replace("+00:00", "Z"),
    }
    if provider == "sysmon":
        return _sysmon_event_data(event_id, base, fields, process, command, file_path, parent, user)
    if provider == "windows_security":
        return _security_event_data(event_id, fields, event, user, sid)
    if provider == "windows_system":
        return {
            "ServiceName": str(fields.get("service_name") or "AGCanarySvc"),
            "ImagePath": file_path,
            "ServiceType": "user mode service",
            "StartType": "demand start",
            "AccountName": "LocalSystem",
        }
    if provider == "windows_defender":
        return {
            "Product Name": "Microsoft Defender Antivirus",
            "Product Version": "4.18.24050.7",
            "Configuration": str(fields.get("rule_name") or "ConfigurationChanged"),
            "New Value": command,
            "Old Value": "DisableRealtimeMonitoring=False",
            "User": user,
        }
    if provider == "windows_powershell":
        return {
            "MessageNumber": "1",
            "MessageTotal": "1",
            "ScriptBlockText": command,
            "ScriptBlockId": "4d3a6d79-bc5f-4c49-8f7f-adversarygraph",
            "Path": str(fields.get("file_path") or ""),
        }
    return base


def _sysmon_event_data(
    event_id: str,
    base: dict[str, object],
    fields: dict[str, object],
    process: str,
    command: str,
    file_path: str,
    parent: str,
    user: str,
) -> dict[str, object]:
    image = _windows_image_path(process, file_path)
    parent_image = _windows_image_path(parent, parent)
    if event_id == "1":
        return {
            **base,
            "ProcessGuid": "{A1B2C3D4-0001-0000-0000-000000000001}",
            "ProcessId": "4824",
            "Image": image,
            "FileVersion": "-",
            "Description": str(fields.get("description") or "-"),
            "Product": str(fields.get("source_product") or "-"),
            "Company": str(fields.get("source_vendor") or "-"),
            "OriginalFileName": process,
            "CommandLine": command,
            "CurrentDirectory": "C:\\Users\\Public\\",
            "User": user,
            "LogonGuid": "{A1B2C3D4-1111-2222-3333-000000000001}",
            "LogonId": "0x3e7",
            "TerminalSessionId": "1",
            "IntegrityLevel": "Medium",
            "Hashes": str(fields.get("file_hash") or "SHA256=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
            "ParentProcessGuid": "{A1B2C3D4-0001-0000-0000-000000000000}",
            "ParentProcessId": "3920",
            "ParentImage": parent_image,
            "ParentCommandLine": str(fields.get("parent_command") or parent),
        }
    if event_id == "3":
        return {
            **base,
            "ProcessGuid": "{A1B2C3D4-0003-0000-0000-000000000003}",
            "ProcessId": "4824",
            "Image": image,
            "User": user,
            "Protocol": str(fields.get("protocol") or "tcp"),
            "Initiated": "true",
            "SourceIsIpv6": "false",
            "SourceIp": str(fields.get("src_ip") or "10.10.10.25"),
            "SourceHostname": "AG-WIN-LAB01",
            "SourcePort": "51514",
            "DestinationIsIpv6": "false",
            "DestinationIp": str(fields.get("destination_ip") or fields.get("dest_ip") or "203.0.113.20"),
            "DestinationHostname": str(fields.get("destination_domain") or "relay.example.test"),
            "DestinationPort": str(fields.get("destination_port") or fields.get("dest_port") or "443"),
        }
    if event_id == "7":
        return {
            **base,
            "Image": _windows_image_path(str(fields.get("process") or "signed-app.exe"), str(fields.get("process") or "signed-app.exe")),
            "ImageLoaded": file_path,
            "FileVersion": "-",
            "Description": "-",
            "Product": "-",
            "Company": "-",
            "OriginalFileName": file_path.rsplit("\\", 1)[-1],
            "Hashes": str(fields.get("file_hash") or "SHA256=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
            "Signed": "false",
            "Signature": str(fields.get("signature") or "Unsigned"),
            "SignatureStatus": "Unavailable",
        }
    if event_id == "8":
        return {
            **base,
            "SourceProcessGuid": "{A1B2C3D4-0008-0000-0000-000000000008}",
            "SourceProcessId": "4824",
            "SourceImage": str(fields.get("source_image") or image),
            "TargetProcessGuid": "{A1B2C3D4-0008-0000-0000-000000000009}",
            "TargetProcessId": "3920",
            "TargetImage": str(fields.get("target_image") or "C:\\Windows\\explorer.exe"),
            "NewThreadId": "6840",
            "StartAddress": "0x000001d4f1000000",
            "StartModule": "-",
            "StartFunction": "-",
        }
    if event_id == "11":
        return {**base, "ProcessGuid": "{A1B2C3D4-0011-0000-0000-000000000011}", "ProcessId": "4824", "Image": image, "TargetFilename": file_path, "CreationUtcTime": base["UtcTime"], "User": user}
    if event_id == "13":
        return {**base, "EventType": "SetValue", "UtcTime": base["UtcTime"], "ProcessGuid": "{A1B2C3D4-0013-0000-0000-000000000013}", "ProcessId": "4824", "Image": image, "TargetObject": str(fields.get("registry_key") or file_path), "Details": str(fields.get("details") or command), "User": user}
    if event_id == "19":
        return {**base, "EventType": "WmiFilterEvent", "Operation": "Created", "User": user, "EventNamespace": "root\\subscription", "Name": "AGCanaryFilter", "Query": "SELECT * FROM __InstanceModificationEvent", "QueryLanguage": "WQL"}
    if event_id == "23":
        return {**base, "ProcessGuid": "{A1B2C3D4-0023-0000-0000-000000000023}", "ProcessId": "4824", "User": user, "Image": image, "TargetFilename": file_path, "Hashes": str(fields.get("file_hash") or "-"), "IsExecutable": "true", "Archived": "false"}
    return base


def _security_event_data(event_id: str, fields: dict[str, object], event: dict[str, object], user: str, sid: str) -> dict[str, object]:
    target_user = str(fields.get("target_user") or user.split("\\")[-1])
    src_ip = str(fields.get("src_ip") or fields.get("destination_ip") or "10.10.20.55")
    if event_id == "4624":
        return {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "AG-WIN-LAB01$",
            "SubjectDomainName": "AGLAB",
            "SubjectLogonId": "0x3e7",
            "TargetUserSid": sid,
            "TargetUserName": target_user,
            "TargetDomainName": "AGLAB",
            "TargetLogonId": "0x5a4b3",
            "LogonType": str(fields.get("logon_type") or "3"),
            "LogonProcessName": "User32",
            "AuthenticationPackageName": str(fields.get("authentication_package") or "Negotiate"),
            "WorkstationName": "AG-SOURCE01",
            "IpAddress": src_ip,
            "IpPort": "51514",
            "ProcessName": str(fields.get("process") or event.get("process") or "-"),
        }
    if event_id == "4728":
        return {
            "MemberName": f"CN={target_user},CN=Users,DC=adversarygraph,DC=local",
            "MemberSid": sid,
            "TargetUserName": str(fields.get("object") or "Domain Admins"),
            "TargetDomainName": "AGLAB",
            "TargetSid": "S-1-5-21-1111111111-2222222222-3333333333-512",
            "SubjectUserSid": "S-1-5-21-1111111111-2222222222-3333333333-500",
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "AGLAB",
            "SubjectLogonId": "0x3e7",
        }
    if event_id == "5140":
        return {"SubjectUserSid": sid, "SubjectUserName": target_user, "SubjectDomainName": "AGLAB", "SubjectLogonId": "0x5a4b3", "ShareName": str(fields.get("share_name") or "\\\\*\\ADMIN$"), "ShareLocalPath": "\\\\??\\C:\\Windows", "IpAddress": src_ip, "IpPort": "51514"}
    if event_id == "4663":
        return {"SubjectUserSid": sid, "SubjectUserName": target_user, "SubjectDomainName": "AGLAB", "ObjectServer": "Security", "ObjectType": "File", "ObjectName": str(fields.get("object_path") or fields.get("file_path") or "\\\\fileserver01\\finance\\payroll.xlsx"), "AccessMask": "0x1", "AccessList": "%%4416", "ProcessName": str(fields.get("process") or "robocopy.exe")}
    if event_id == "1102":
        return {"SubjectUserSid": sid, "SubjectUserName": target_user, "SubjectDomainName": "AGLAB", "SubjectLogonId": "0x3e7"}
    return {"TargetUserName": target_user, "IpAddress": src_ip}


def _windows_event_xml(provider_name: str, provider_guid: str, channel: str, computer: str, timestamp: str, event_id: str, data: dict[str, object]) -> str:
    data_xml = "".join(f'<Data Name="{escape(str(key))}">{escape(str(value))}</Data>' for key, value in data.items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f'<Provider Name="{escape(provider_name)}" Guid="{escape(provider_guid)}"/>'
        f"<EventID>{escape(str(event_id))}</EventID>"
        "<Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
        f'<TimeCreated SystemTime="{escape(timestamp)}"/>'
        "<EventRecordID>10001</EventRecordID>"
        f"<Channel>{escape(channel)}</Channel><Computer>{escape(computer)}</Computer><Security UserID=\"S-1-5-18\"/>"
        "</System>"
        f"<EventData>{data_xml}</EventData>"
        "</Event>"
    )


def _vendor_event_record(event: dict[str, object], category: str, provider: str, event_id: str, event_name: str) -> dict[str, object]:
    fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
    return {
        "timestamp": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "observer": {"vendor": fields.get("source_vendor") or "AdversaryGraph", "product": fields.get("source_product") or provider},
        "event": {"kind": "event", "provider": provider, "code": event_id, "action": event_name, "category": _ecs_category(provider, event_id), "type": _ecs_type(provider, event_id)},
        "host": {"name": event.get("host") or "attack-lab-endpoint"},
        "process": {"name": event.get("process") or fields.get("process") or "", "command_line": event.get("command") or fields.get("command") or ""},
        "url": {"full": fields.get("url") or event.get("url") or ""},
        "destination": {"ip": fields.get("destination_ip") or fields.get("dest_ip") or "", "domain": fields.get("destination_domain") or "", "port": fields.get("destination_port") or fields.get("dest_port") or ""},
        "source": {"ip": fields.get("src_ip") or event.get("client_ip") or ""},
        "rule": {"name": fields.get("rule_name") or ""},
        "adversarygraph": {"module": "Attack Simulation", "simulation_id": event.get("simulation_id") or "", "run_id": event.get("run_id") or "", "atomic_category": category},
        "fields": fields,
    }


def _windows_image_path(process: str, fallback: str) -> str:
    value = fallback if "\\" in fallback else process
    if "\\" in value:
        return value
    system32 = {"cmd.exe", "powershell.exe", "wmic.exe", "net.exe", "nltest.exe", "netstat.exe", "vssadmin.exe", "reg.exe", "wevtutil.exe", "schtasks.exe", "sc.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "icacls.exe", "attrib.exe"}
    base = "C:\\Windows\\System32" if value.lower() in system32 else "C:\\Users\\Public"
    return f"{base}\\{value}"


def _security_sid(fields: dict[str, object], event: dict[str, object]) -> str:
    return str(fields.get("sid") or event.get("sid") or "S-1-5-21-1111111111-2222222222-3333333333-1105")


def _stable_event_record_id(event: dict[str, object]) -> int:
    seed = f"{event.get('run_id')}-{event.get('simulation_id')}-{event.get('request_index')}"
    return 100000 + (int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16) % 900000)


def _windows_event_version(provider: str, event_id: str) -> int:
    if provider == "windows_security" and event_id == "4624":
        return 2
    return 5 if provider == "sysmon" else 0


def _windows_level(severity: str) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity.lower(), 4)


def _windows_task(provider: str, event_id: str) -> int:
    if provider == "windows_security":
        return {"4624": 12544, "4728": 13824, "5140": 12808, "4663": 12800, "1102": 104}.get(event_id, 0)
    return int(event_id) if event_id.isdigit() and provider == "sysmon" else 0


def _windows_keywords(provider: str) -> str:
    return "0x8020000000000000" if provider == "windows_security" else "0x8000000000000000"


def _ecs_category(provider: str, event_id: str) -> list[str]:
    if provider in {"windows_security", "windows_system"}:
        return ["authentication"] if event_id == "4624" else ["iam"]
    if event_id in {"3"} or provider in {"proxy", "firewall"}:
        return ["network"]
    if event_id in {"11", "23"}:
        return ["file"]
    if event_id in {"13", "19"}:
        return ["registry"]
    return ["process"]


def _ecs_type(provider: str, event_id: str) -> list[str]:
    if event_id == "4624":
        return ["start", "info"]
    if event_id in {"11"}:
        return ["creation"]
    if event_id in {"23"}:
        return ["deletion"]
    if event_id in {"13", "19"}:
        return ["change"]
    return ["info"]


def _endpoint_provider_fields(category: str) -> tuple[str, str, str]:
    if category.startswith("atomic_"):
        return ("edr", "ATOMIC", "AtomicArtifact")
    if category == "shadow_file_access":
        return ("auditd", "SYSCALL", "FileAccess")
    if category == "mimikatz_lsass":
        return ("sysmon", "1", "ProcessCreate")
    if category == "lsass_dump":
        return ("sysmon", "10", "ProcessAccess")
    if category == "run_key_persistence":
        return ("sysmon", "13", "RegistryValueSet")
    if category in {"scheduled_task", "service_creation"}:
        return ("sysmon", "1", "ProcessCreate")
    if category == "file_discovery":
        return ("edr", "FILE_DISCOVERY", "FileDiscovery")
    if category in {
        "powershell_encoded",
        "cmd_shell",
        "certutil_transfer",
        "rundll32_proxy",
        "regsvr32_proxy",
        "system_discovery",
        "user_discovery",
        "process_discovery",
        "network_config_discovery",
        "remote_system_discovery",
        "software_discovery",
    }:
        return ("sysmon", "1", "ProcessCreate")
    return ("edr", "-", "EndpointActivity")


def _severity(category: str) -> str:
    if category.startswith("atomic_"):
        return "medium"
    if category in {
        "shadow_file_access",
        "mimikatz_lsass",
        "lsass_dump",
        "powershell_encoded",
        "certutil_transfer",
        "run_key_persistence",
        "scheduled_task",
        "service_creation",
        "rundll32_proxy",
        "regsvr32_proxy",
    }:
        return "high"
    if category in {"cmd_shell", "system_discovery", "file_discovery", "user_discovery", "process_discovery", "network_config_discovery", "remote_system_discovery", "software_discovery"}:
        return "medium"
    return "low"


def _process_for_category(category: str) -> str:
    return {
        "shadow_file_access": "cat",
        "mimikatz_lsass": "mimikatz.exe",
        "lsass_dump": "procdump64.exe",
        "powershell_encoded": "powershell.exe",
        "cmd_shell": "cmd.exe",
        "certutil_transfer": "certutil.exe",
        "run_key_persistence": "reg.exe",
        "scheduled_task": "schtasks.exe",
        "service_creation": "sc.exe",
        "rundll32_proxy": "rundll32.exe",
        "regsvr32_proxy": "regsvr32.exe",
        "system_discovery": "systeminfo.exe",
        "file_discovery": "cmd.exe",
        "user_discovery": "whoami.exe",
        "process_discovery": "tasklist.exe",
        "network_config_discovery": "ipconfig.exe",
        "remote_system_discovery": "net.exe",
        "software_discovery": "wmic.exe",
    }.get(category, "-")


def _file_for_category(category: str) -> str:
    return "/etc/shadow" if category == "shadow_file_access" else "-"


def _endpoint_log_path() -> Path:
    return LOG_DIR / "lab-endpoint.log"


def _endpoint_jsonl_path() -> Path:
    return LOG_DIR / "lab-endpoint.jsonl"


def _append_jsonl(path: Path, event: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def _append_text_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line.rstrip("\n") + "\n")


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), EndpointLabHandler)
    print(f"AdversaryGraph Docker attack lab endpoint target listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()
