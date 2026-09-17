from __future__ import annotations

import json
from pathlib import Path

from breachscope.canonical import build_canonical_event
from breachscope.collector import load_jsonl_events
from breachscope.utils import get_event_identity_key, get_windows_event_record_identity
from scripts.evaluate_external_holdout import _record_to_event, event_identity_payload


def _winlogbeat_record(record_number: str = "1446958") -> dict:
    return {
        "@timestamp": "2019-05-14T22:31:14.252Z",
        "computer_name": "HR001.shire.com",
        "source_name": "Microsoft-Windows-Sysmon",
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "record_number": record_number,
        "host": {"name": "WECserver"},
        "user": {
            "name": "SYSTEM",
            "domain": "NT AUTHORITY",
            "identifier": "S-1-5-18",
        },
        "event_data": {
            "ProcessId": "748",
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": r"NT AUTHORITY\SYSTEM",
        },
    }


def test_external_adapter_preserves_lowercase_winlogbeat_endpoint_identity() -> None:
    record = _winlogbeat_record()
    identity = event_identity_payload(record)
    event = _record_to_event(record)

    assert identity["host"] == "HR001.shire.com"
    assert identity["source"] == "Microsoft-Windows-Sysmon"
    assert identity["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert identity["event_record_id"] == "1446958"
    assert identity["user"] == r"NT AUTHORITY\SYSTEM"
    assert identity["command_line"] == "cmd.exe /c whoami"

    assert event.host == "HR001.shire.com"
    assert event.source == "Microsoft-Windows-Sysmon"
    assert event.command_line == "cmd.exe /c whoami"
    assert event.raw["event_record_id"] == "1446958"
    assert event.raw["canonical"]["host"]["name"] == "HR001.shire.com"
    assert get_windows_event_record_identity(event) == (
        "Microsoft-Windows-Sysmon/Operational",
        "1446958",
    )


def test_lowercase_record_numbers_remain_distinct() -> None:
    first = _record_to_event(_winlogbeat_record("1446958"))
    second = _record_to_event(_winlogbeat_record("1446959"))
    assert get_event_identity_key(first) != get_event_identity_key(second)


def test_collector_normalizes_lowercase_winlogbeat_jsonl(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(_winlogbeat_record()) + "\n", encoding="utf-8")

    events = list(load_jsonl_events(source))
    assert len(events) == 1
    event = events[0]
    assert event.host == "HR001.shire.com"
    assert event.source == "Microsoft-Windows-Sysmon"
    assert event.user == r"NT AUTHORITY\SYSTEM"
    assert event.command_line == "cmd.exe /c whoami"
    assert event.raw["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event.raw["event_record_id"] == "1446958"
    assert event.raw["canonical"]["host"]["name"] == "HR001.shire.com"
    assert event.raw["canonical"]["event"]["provider"] == "windows.sysmon"


def test_canonical_mapping_values_do_not_stringify_dicts() -> None:
    canonical = build_canonical_event(
        {
            "event_id": 1,
            "source": "Microsoft-Windows-Sysmon",
            "host": {"name": "HR001.shire.com"},
            "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
            "raw": {"event_data": {"Image": r"C:\Windows\System32\cmd.exe"}},
        }
    )
    assert canonical["host"]["name"] == "HR001.shire.com"
    assert canonical["user"]["name"] == "SYSTEM"
