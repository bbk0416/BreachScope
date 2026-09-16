from scripts.evaluate_external_holdout import _record_to_event


def test_record_to_event_uses_converted_nested_raw_payload() -> None:
    converted = {
        "timestamp": "2026-09-08T00:00:00Z",
        "host": "dc1.example.test",
        "source": "Microsoft-Windows-Security-Auditing",
        "event_id": "4661",
        "user": "EXAMPLE\\user01",
        "command_line": "",
        "raw": {
            "ObjectName": "S-1-5-21-1-2-3-512",
            "ObjectType": "SAM_GROUP",
            "ObjectServer": "Security Account Manager",
        },
    }

    event = _record_to_event(converted)

    assert event.timestamp == converted["timestamp"]
    assert event.host == converted["host"]
    assert event.source == converted["source"]
    assert str(event.event_id) == "4661"
    assert event.raw == converted["raw"]
    assert event.raw["ObjectName"].endswith("-512")


def test_record_to_event_keeps_legacy_flat_raw_when_no_nested_raw_exists() -> None:
    record = {
        "timestamp": "2026-09-08T00:00:00Z",
        "host": "host1",
        "source": "custom",
        "event_id": "1",
        "user": "",
        "command_line": "test",
        "CustomField": "value",
    }

    event = _record_to_event(record)

    assert event.raw == record
    assert event.raw["CustomField"] == "value"

def test_record_to_event_reconstructs_flat_windows_jsonl_endpoint_and_canonical():
    record = {
        "@timestamp": "2020-05-02T02:55:57.748Z",
        "host": "wec.internal.cloudapp.net",
        "Hostname": "SCRANTON.dmevals.local",
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "EventID": 4688,
        "RecordNumber": 70089,
        "SubjectUserName": "pbeesly",
        "CommandLine": "powershell.exe -enc ZQB4AGkAdAA=",
        "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    }

    event = _record_to_event(record)

    assert event.timestamp == record["@timestamp"]
    assert event.host == "SCRANTON.dmevals.local"
    assert event.source == "Microsoft-Windows-Security-Auditing"
    assert str(event.event_id) == "4688"
    assert event.user == "pbeesly"
    assert event.command_line == record["CommandLine"]
    assert event.raw["host"] == "wec.internal.cloudapp.net"
    assert event.raw["Hostname"] == "SCRANTON.dmevals.local"
    assert event.raw["canonical"]["host"]["name"] == "SCRANTON.dmevals.local"
    assert event.raw["canonical"]["event"]["category"] == "process"
    assert event.raw["canonical"]["event"]["action"] == "process_start"


def test_flat_windows_identity_uses_endpoint_and_record_number():
    from scripts.evaluate_external_holdout import event_identity_payload

    record = {
        "@timestamp": "2020-05-02T02:55:57.748Z",
        "host": "wec.internal.cloudapp.net",
        "Hostname": "NASHUA.dmevals.local",
        "SourceName": "Microsoft-Windows-Sysmon",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "RecordNumber": 12345,
        "User": r"DMEVALS\pbeesly",
        "CommandLine": "cmd.exe /c whoami",
    }

    identity = event_identity_payload(record)

    assert identity["host"] == "NASHUA.dmevals.local"
    assert identity["source"] == "Microsoft-Windows-Sysmon"
    assert identity["event_id"] == "1"
    assert identity["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert identity["event_record_id"] == "12345"
