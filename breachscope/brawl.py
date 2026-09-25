"""MITRE BRAWL documented-schema adapter.

This module is intentionally implemented from the public
mitre/brawl-public-game-001 README/schema description. It does not require
or inspect the released raw event archive.
"""
from __future__ import annotations

from typing import Any, Mapping

from .canonical import enrich_event_dict
from .ingest import _extract_from_xml
from .schemas import Event


class BrawlAdapterError(ValueError):
    """Raised when a documented BRAWL record cannot be normalized safely."""


_SYSMON_EVENT_IDS: dict[tuple[str, str], str] = {
    ("process", "create"): "1",
    ("file", "attr_modify"): "2",
    ("flow", "start"): "3",
    ("process", "terminate"): "5",
    ("driver", "load"): "6",
    ("module", "load"): "7",
    ("thread", "create"): "8",
    ("threat", "remote_create"): "8",
}

_FIELD_ALIASES: dict[str, str] = {
    "command_line": "CommandLine",
    "exe": "Image",
    "image_path": "Image",
    "parent_exe": "ParentImage",
    "parent_image_path": "ParentImage",
    "pid": "ProcessId",
    "ppid": "ParentProcessId",
    "user": "User",
    "src_ip": "SourceIp",
    "src_port": "SourcePort",
    "dest_ip": "DestinationIp",
    "dest_port": "DestinationPort",
    "protocol": "Protocol",
    "file_path": "TargetFilename",
}


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_actions(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip().casefold() for item in value if str(item).strip()]
    if value in (None, ""):
        return []
    return [str(value).strip().casefold()]


def _normalized_sysmon_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {str(key): value for key, value in fields.items()}

    folded = {str(key).casefold(): value for key, value in fields.items()}
    for source_name, target_name in _FIELD_ALIASES.items():
        value = folded.get(source_name)
        if value not in (None, "") and target_name not in normalized:
            normalized[target_name] = value

    if "Hashes" not in normalized:
        hashes: list[str] = []
        for source_name, label in (
            ("md5_hash", "MD5"),
            ("sha1_hash", "SHA1"),
            ("sha256_hash", "SHA256"),
        ):
            value = folded.get(source_name)
            if value not in (None, ""):
                hashes.append(f"{label}={value}")
        if hashes:
            normalized["Hashes"] = ",".join(hashes)

    return normalized


def _sysmon_event_id(object_name: str, actions: list[str]) -> str:
    obj = object_name.strip().casefold()
    for action in actions:
        event_id = _SYSMON_EVENT_IDS.get((obj, action))
        if event_id:
            return event_id
    return ""


def event_from_brawl_sysmon(record: Mapping[str, Any]) -> Event:
    """Normalize one documented BRAWL Sysmon record."""
    data_model = _as_mapping(record.get("data_model"))
    object_name = str(data_model.get("object") or "")
    actions = _as_actions(data_model.get("action"))
    fields = _normalized_sysmon_fields(_as_mapping(data_model.get("fields")))

    event_id = _sysmon_event_id(object_name, actions)
    command_line = fields.get("CommandLine")
    user = fields.get("User")

    raw = dict(record)
    raw["event_data"] = dict(fields)
    for key, value in fields.items():
        raw.setdefault(key, value)
    raw["brawl_adapter"] = {
        "record_type": "sysmon",
        "object": object_name,
        "actions": actions,
        "event_id_mapping": event_id or None,
    }

    candidate = {
        "timestamp": str(record.get("@timestamp") or ""),
        "host": str(record.get("host") or "unknown"),
        "source": "Microsoft-Windows-Sysmon",
        "event_id": event_id,
        "level": "",
        "user": "" if user in (None, "") else str(user),
        "command_line": None if command_line in (None, "") else str(command_line),
        "raw": raw,
    }
    return Event(**enrich_event_dict(candidate))


def event_from_brawl_win_event(record: Mapping[str, Any]) -> Event:
    """Normalize one documented BRAWL Windows Event record."""
    xml = record.get("raw")
    if not isinstance(xml, str) or not xml.strip():
        raise BrawlAdapterError("BRAWL win_event record must contain raw Windows Event XML")

    parsed = _extract_from_xml(xml)
    if not isinstance(parsed, dict):
        raise BrawlAdapterError("BRAWL win_event raw XML could not be parsed")

    if not parsed.get("timestamp"):
        parsed["timestamp"] = str(record.get("@timestamp") or "")
    if not parsed.get("host"):
        parsed["host"] = str(record.get("host") or "unknown")

    raw = parsed.get("raw")
    if not isinstance(raw, dict):
        raw = {}
        parsed["raw"] = raw
    raw["brawl_record"] = {key: value for key, value in record.items() if key != "raw"}
    raw["brawl_adapter"] = {"record_type": "win_event"}

    return Event(**parsed)


def event_from_brawl_record(record: Mapping[str, Any]) -> Event | None:
    """Return an Event for documented BRAWL host telemetry, otherwise None."""
    record_type = str(record.get("type") or "").strip().casefold()
    if record_type == "sysmon":
        return event_from_brawl_sysmon(record)
    if record_type == "win_event":
        return event_from_brawl_win_event(record)
    return None


def extract_bsf_steps(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Extract attack-step ground truth from one documented BRAWL BSF record.

    The result preserves upstream event references and ATT&CK annotations
    without inventing event-level malicious or benign labels.
    """
    bsf = record.get("bsf")
    if not isinstance(bsf, list):
        return []

    nodes = [node for node in bsf if isinstance(node, Mapping)]
    by_id = {
        str(node.get("id")): node
        for node in nodes
        if node.get("id") not in (None, "")
    }

    results: list[dict[str, Any]] = []
    for node in nodes:
        if str(node.get("nodetype") or "").casefold() != "step":
            continue

        refs = node.get("events")
        event_ids = [str(value) for value in refs] if isinstance(refs, list) else []
        referenced_events = [
            dict(by_id[event_id])
            for event_id in event_ids
            if event_id in by_id
            and str(by_id[event_id].get("nodetype") or "").casefold() == "event"
        ]

        attack_info = node.get("attack_info")
        techniques: list[dict[str, Any]] = []
        if isinstance(attack_info, list):
            for item in attack_info:
                if not isinstance(item, Mapping):
                    continue
                techniques.append(
                    {
                        "technique_id": str(item.get("technique_id") or ""),
                        "technique_name": str(item.get("technique_name") or ""),
                        "tactic": list(item.get("tactic") or [])
                        if isinstance(item.get("tactic"), list)
                        else [],
                    }
                )

        results.append(
            {
                "step_id": str(node.get("id") or ""),
                "techniques": techniques,
                "event_ids": event_ids,
                "events": referenced_events,
            }
        )

    return results


__all__ = [
    "BrawlAdapterError",
    "event_from_brawl_record",
    "event_from_brawl_sysmon",
    "event_from_brawl_win_event",
    "extract_bsf_steps",
]
