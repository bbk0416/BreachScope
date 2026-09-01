from __future__ import annotations

from typing import Any, Mapping

SCHEMA_VERSION = "1.0"


def _local_provider(value: Any) -> str:
    text = str(value or "").strip()
    lowered = text.casefold()
    if "security-auditing" in lowered or lowered in {"security", "windows security"}:
        return "windows.security"
    if "sysmon" in lowered:
        return "windows.sysmon"
    if "powershell" in lowered:
        return "windows.powershell"
    if "service control manager" in lowered:
        return "windows.service_control_manager"
    return text


def _first_scalar(value: Any) -> Any:
    if isinstance(value, list):
        for item in value:
            scalar = _first_scalar(item)
            if scalar not in (None, ""):
                return scalar
        return None
    return value


def _text(value: Any) -> str | None:
    value = _first_scalar(value)
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _intish(value: Any) -> int | str | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        try:
            return int(text)
        except (TypeError, ValueError):
            return text


def _lookup(data: Mapping[str, Any], *names: str) -> Any:
    if not data:
        return None
    folded = {str(k).casefold(): v for k, v in data.items()}
    for name in names:
        if name in data:
            value = data[name]
            if _first_scalar(value) not in (None, ""):
                return value
        value = folded.get(name.casefold())
        if _first_scalar(value) not in (None, ""):
            return value
    return None


def _raw_fields(event: Mapping[str, Any]) -> dict[str, Any]:
    raw = event.get("raw")
    if not isinstance(raw, Mapping):
        raw = {}

    fields: dict[str, Any] = {}
    event_data = raw.get("event_data")
    if isinstance(event_data, Mapping):
        fields.update(event_data)

    for key, value in raw.items():
        if key in {"event_data", "event_data_records", "system", "user_data", "canonical"}:
            continue
        fields[key] = value

    for key, value in event.items():
        if key not in {"raw", "canonical"} and key not in fields:
            fields[key] = value
    return fields


def _event_id(event: Mapping[str, Any], raw: Mapping[str, Any]) -> int | str | None:
    value = event.get("event_id")
    if value in (None, ""):
        system = raw.get("system")
        if isinstance(system, Mapping):
            value = _lookup(system, "EventID")
    return _intish(value)


def _provider(event: Mapping[str, Any], raw: Mapping[str, Any]) -> str:
    value = event.get("source")
    system = raw.get("system")
    if value in (None, "") and isinstance(system, Mapping):
        value = _lookup(system, "ProviderName", "Provider")
    return _local_provider(value)


def _taxonomy(provider: str, event_id: int | str | None) -> tuple[str, str]:
    key = (provider, str(event_id) if event_id is not None else "")
    mapping = {
        ("windows.security", "4688"): ("process", "process_start"),
        ("windows.sysmon", "1"): ("process", "process_start"),
        ("windows.sysmon", "3"): ("network", "connection"),
        ("windows.security", "4624"): ("authentication", "logon_success"),
        ("windows.security", "4625"): ("authentication", "logon_failure"),
        ("windows.security", "4698"): ("task", "task_create"),
        ("windows.security", "1102"): ("log", "log_clear"),
        ("windows.powershell", "4104"): ("script", "script_block"),
        ("windows.service_control_manager", "7045"): ("service", "service_install"),
    }
    return mapping.get(key, ("unknown", "observed"))


def _generic_user(event: Mapping[str, Any], fields: Mapping[str, Any]) -> dict[str, Any]:
    name = _text(
        _lookup(
            fields,
            "TargetUserName",
            "SubjectUserName",
            "User",
            "UserName",
            "AccountName",
        )
    ) or _text(event.get("user"))
    sid = _text(_lookup(fields, "TargetUserSid", "SubjectUserSid", "UserSid", "UserID"))
    result: dict[str, Any] = {}
    if name:
        result["name"] = name
    if sid:
        result["id"] = sid
    return result


def _process_fields(
    provider: str,
    event_id: int | str | None,
    event: Mapping[str, Any],
    fields: Mapping[str, Any],
) -> dict[str, Any]:
    eid = str(event_id) if event_id is not None else ""

    if provider == "windows.security" and eid == "4688":
        pid = _lookup(fields, "NewProcessId")
        parent_pid = _lookup(fields, "ProcessId", "CreatorProcessId")
        executable = _lookup(fields, "NewProcessName")
        parent_executable = _lookup(fields, "ParentProcessName")
    else:
        pid = _lookup(fields, "ProcessId", "NewProcessId")
        parent_pid = _lookup(fields, "ParentProcessId", "CreatorProcessId")
        executable = _lookup(fields, "Image", "NewProcessName", "ProcessName")
        parent_executable = _lookup(fields, "ParentImage", "ParentProcessName")

    result: dict[str, Any] = {}
    pairs = {
        "pid": _intish(pid),
        "parent_pid": _intish(parent_pid),
        "executable": _text(executable),
        "parent_executable": _text(parent_executable),
        "command_line": _text(_lookup(fields, "CommandLine", "ProcessCommandLine"))
        or _text(event.get("command_line")),
        "guid": _text(_lookup(fields, "ProcessGuid")),
        "parent_guid": _text(_lookup(fields, "ParentProcessGuid")),
        "current_directory": _text(_lookup(fields, "CurrentDirectory")),
        "integrity_level": _text(_lookup(fields, "IntegrityLevel", "MandatoryLabel")),
        "hashes": _text(_lookup(fields, "Hashes", "Hash")),
    }
    for key, value in pairs.items():
        if value not in (None, ""):
            result[key] = value
    return result


def _network_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pairs = {
        "source_ip": _text(_lookup(fields, "SourceIp", "IpAddress", "SourceAddress")),
        "source_port": _intish(_lookup(fields, "SourcePort")),
        "destination_ip": _text(_lookup(fields, "DestinationIp", "DestAddress")),
        "destination_port": _intish(_lookup(fields, "DestinationPort", "DestPort")),
        "destination_hostname": _text(_lookup(fields, "DestinationHostname", "DestinationHostName")),
        "protocol": _text(_lookup(fields, "Protocol")),
        "initiated": _text(_lookup(fields, "Initiated")),
    }
    for key, value in pairs.items():
        if value not in (None, ""):
            result[key] = value
    return result


def _authentication_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pairs = {
        "logon_type": _intish(_lookup(fields, "LogonType")),
        "authentication_package": _text(_lookup(fields, "AuthenticationPackageName")),
        "logon_process": _text(_lookup(fields, "LogonProcessName")),
        "workstation": _text(_lookup(fields, "WorkstationName")),
        "ip_address": _text(_lookup(fields, "IpAddress", "SourceIp")),
        "ip_port": _intish(_lookup(fields, "IpPort", "SourcePort")),
    }
    for key, value in pairs.items():
        if value not in (None, ""):
            result[key] = value
    return result


def build_canonical_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Build a stable, provider-neutral event view without deleting raw evidence."""
    raw_obj = event.get("raw")
    raw: Mapping[str, Any] = raw_obj if isinstance(raw_obj, Mapping) else {}
    fields = _raw_fields(event)
    event_id = _event_id(event, raw)
    provider = _provider(event, raw)
    category, action = _taxonomy(provider, event_id)

    canonical: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event": {
            "category": category,
            "action": action,
        },
    }

    if event_id is not None:
        canonical["event"]["code"] = event_id
    if provider:
        canonical["event"]["provider"] = provider

    host = _text(event.get("host")) or _text(_lookup(fields, "Computer", "Hostname", "Host"))
    if not host:
        system = raw.get("system")
        if isinstance(system, Mapping):
            host = _text(_lookup(system, "Computer"))
    if host:
        canonical["host"] = {"name": host}

    user = _generic_user(event, fields)
    if user:
        canonical["user"] = user

    session_id = _text(_lookup(fields, "TargetLogonId", "SubjectLogonId", "LogonId", "SessionId"))
    if session_id:
        canonical["session"] = {"id": session_id}

    process = _process_fields(provider, event_id, event, fields)
    if process:
        canonical["process"] = process

    network = _network_fields(fields)
    if network:
        canonical["network"] = network

    if category == "authentication":
        auth = _authentication_fields(fields)
        if auth:
            canonical["authentication"] = auth

    file_path = _text(_lookup(fields, "TargetFilename", "FileName", "Path"))
    if file_path and category not in {"script"}:
        canonical["file"] = {"path": file_path}

    registry_path = _text(_lookup(fields, "TargetObject", "ObjectName", "RegistryPath"))
    if registry_path:
        canonical["registry"] = {"path": registry_path}

    if category == "script":
        script_text = _text(_lookup(fields, "ScriptBlockText", "Payload", "Message"))
        script_path = _text(_lookup(fields, "Path", "ScriptName"))
        script: dict[str, Any] = {}
        if script_text:
            script["text"] = script_text
        if script_path:
            script["path"] = script_path
        if script:
            canonical["script"] = script

    if category == "service":
        service: dict[str, Any] = {}
        name = _text(_lookup(fields, "ServiceName"))
        image_path = _text(_lookup(fields, "ImagePath", "ServiceFileName"))
        start_type = _text(_lookup(fields, "StartType", "ServiceStartType"))
        account = _text(_lookup(fields, "AccountName", "ServiceAccount"))
        if name:
            service["name"] = name
        if image_path:
            service["image_path"] = image_path
        if start_type:
            service["start_type"] = start_type
        if account:
            service["account"] = account
        if service:
            canonical["service"] = service

    if category == "task":
        task: dict[str, Any] = {}
        name = _text(_lookup(fields, "TaskName"))
        content = _text(_lookup(fields, "TaskContent", "TaskContentNew"))
        if name:
            task["name"] = name
        if content:
            task["content"] = content
        if task:
            canonical["task"] = task

    return canonical


def enrich_event_dict(event: dict[str, Any]) -> dict[str, Any]:
    """Attach canonical data under raw['canonical'] while preserving legacy shape."""
    raw = event.get("raw")
    if not isinstance(raw, dict):
        raw = {}
        event["raw"] = raw
    raw["canonical"] = build_canonical_event(event)
    return event
