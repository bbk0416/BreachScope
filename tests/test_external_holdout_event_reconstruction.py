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
