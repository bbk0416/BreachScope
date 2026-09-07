from __future__ import annotations

import json
from pathlib import Path

from breachscope.normalizer import normalize
from breachscope.pipeline import Pipeline
from breachscope.schemas import Event
from breachscope.utils import get_windows_event_record_identity


def _event(*, record_id: str | None, host: str = "WIN-A") -> Event:
    raw = {
        "timestamp": "2026-09-07T12:00:00+00:00",
        "host": host,
        "source": "Microsoft-Windows-Security-Auditing",
        "event_id": "4688",
    }
    if record_id is not None:
        raw["System"] = {
            "Channel": "Security",
            "EventRecordID": record_id,
        }
    return Event(
        timestamp=raw["timestamp"],
        host=host,
        source=raw["source"],
        event_id=raw["event_id"],
        user="alice",
        command_line=" cmd.exe /c whoami ",
        raw=raw,
    )


def _generic_event_with_business_record_id() -> Event:
    return Event(
        timestamp="2026-09-07T12:00:00+00:00",
        host="APP-A",
        source="application",
        event_id="message",
        user="alice",
        command_line="",
        raw={
            "channel": "alerts",
            "record_id": "100",
            "message": "same coarse observation",
        },
    )


def test_normalizer_deduplicates_same_windows_record_identity():
    first = _event(record_id="100", host=" WIN-A ")
    duplicate = _event(record_id="100", host="WIN-A")

    events = list(normalize([first, duplicate]))

    assert events == [first]
    assert first.host == "WIN-A"
    assert first.command_line == "cmd.exe /c whoami"


def test_normalizer_preserves_distinct_windows_record_ids_with_same_coarse_metadata():
    first = _event(record_id="100")
    second = _event(record_id="101")

    events = list(normalize([first, second]))

    assert events == [first, second]


def test_normalizer_preserves_generic_duplicate_rows_without_strong_identity():
    first = _event(record_id=None)
    duplicate = _event(record_id=None)

    events = list(normalize([first, duplicate]))

    assert events == [first, duplicate]


def test_generic_channel_and_record_id_are_not_treated_as_windows_identity():
    first = _generic_event_with_business_record_id()
    duplicate = _generic_event_with_business_record_id()

    assert get_windows_event_record_identity(first) == ("", "")
    assert list(normalize([first, duplicate])) == [first, duplicate]


def test_flattened_eventrecordid_remains_supported_for_windows_identity():
    first = _event(record_id=None)
    first.raw.update({"Channel": "Security", "EventRecordID": "100"})
    duplicate = _event(record_id=None)
    duplicate.raw.update({"Channel": "Security", "EventRecordID": "100"})

    assert get_windows_event_record_identity(first) == ("Security", "100")
    assert list(normalize([first, duplicate])) == [first]


def test_system_record_id_alias_remains_supported_for_windows_identity():
    first = _event(record_id=None)
    first.raw["System"] = {"Channel": "Security", "record_id": "100"}
    duplicate = _event(record_id=None)
    duplicate.raw["System"] = {"Channel": "Security", "record_id": "100"}

    assert get_windows_event_record_identity(first) == ("Security", "100")
    assert list(normalize([first, duplicate])) == [first]


def test_pipeline_max_events_counts_unique_windows_records(tmp_path: Path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    rows = [
        {
            "timestamp": "2026-09-07T12:00:00+00:00",
            "host": "WIN-A",
            "source": "Microsoft-Windows-Security-Auditing",
            "event_id": "4688",
            "System": {"Channel": "Security", "EventRecordID": "100"},
        },
        {
            "timestamp": "2026-09-07T12:00:00+00:00",
            "host": "WIN-A",
            "source": "Microsoft-Windows-Security-Auditing",
            "event_id": "4688",
            "System": {"Channel": "Security", "EventRecordID": "100"},
        },
        {
            "timestamp": "2026-09-07T12:00:01+00:00",
            "host": "WIN-A",
            "source": "Microsoft-Windows-Security-Auditing",
            "event_id": "4688",
            "System": {"Channel": "Security", "EventRecordID": "101"},
        },
    ]
    path = input_dir / "events.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    pipeline = Pipeline(rules_dir=tmp_path / "rules", max_events=2)
    events = pipeline.collect_events(input_dir)

    assert len(events) == 2
    assert [event.raw["System"]["EventRecordID"] for event in events] == ["100", "101"]
