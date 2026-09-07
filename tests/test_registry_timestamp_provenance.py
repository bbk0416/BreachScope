from datetime import datetime, timezone
from types import SimpleNamespace
import subprocess

from breachscope.artifacts import registry


def test_live_registry_marks_timestamp_as_utc_collection_time(monkeypatch):
    target_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

    def fake_run(args, **kwargs):
        if args == ["reg.exe", "query", target_key]:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    f"{target_key}\n"
                    "    ExampleAutorun    REG_SZ    C:\\Tools\\example.exe --start\n"
                ),
                stderr="",
            )
        return SimpleNamespace(returncode=1, stdout="", stderr="not found")

    monkeypatch.setattr(registry.platform, "system", lambda: "Windows")
    monkeypatch.setattr(subprocess, "run", fake_run)

    events = registry.collect_registry()

    assert len(events) == 1
    event = events[0]
    observed = datetime.fromisoformat(event["timestamp"])

    assert observed.tzinfo == timezone.utc
    assert event["source"] == "Registry"
    assert event["event_id"] == "autorun_hklm_run"
    assert event["event_type"] == "autorun_entry"
    assert event["command_line"] == r"C:\Tools\example.exe --start"
    assert event["raw"]["observation_time"] == event["timestamp"]
    assert event["raw"]["timestamp_source"] == "collection_time"
    assert event["raw"]["registry_key_last_write_time_verified"] is False
    assert event["raw"]["registry_key_last_write_times"] == []


def test_live_registry_preserves_spaced_value_name_and_data(monkeypatch):
    target_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    expected_data = r'"%ProgramFiles%\My App\app.exe" --start'

    def fake_run(args, **kwargs):
        if args == ["reg.exe", "query", target_key]:
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    f"{target_key}\n"
                    "    My Startup App    REG_EXPAND_SZ    "
                    '"%ProgramFiles%\\My App\\app.exe" --start\n'
                ),
                stderr="",
            )
        return SimpleNamespace(returncode=1, stdout="", stderr="not found")

    monkeypatch.setattr(registry.platform, "system", lambda: "Windows")
    monkeypatch.setattr(subprocess, "run", fake_run)

    events = registry.collect_registry()

    assert len(events) == 1
    event = events[0]
    assert event["command_line"] == expected_data
    assert event["raw"]["value_name"] == "My Startup App"
    assert event["raw"]["value_type"] == "REG_EXPAND_SZ"
    assert event["raw"]["value_data"] == expected_data
