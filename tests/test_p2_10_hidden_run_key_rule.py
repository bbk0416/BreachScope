from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
RULE_ID = "R-RUNKEY-UNNAMED-13"


def _rules():
    return load_rules(ROOT / "rules")


def _event(
    target_object: str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
    *,
    event_type: str = "SetValue",
    event_id: str = "13",
    source: str = "Microsoft-Windows-Sysmon",
) -> Event:
    return Event(
        timestamp="2026-09-10T00:00:00Z",
        host="host.example.test",
        source=source,
        event_id=event_id,
        command_line="",
        raw={
            "EventType": event_type,
            "TargetObject": target_object,
            "Details": r'"C:\Windows\Tasks\taskhost.exe"',
            "Image": r"C:\Users\Public\tool.exe",
        },
    )


def _matches(event: Event) -> list:
    return [
        finding
        for finding in apply_rules([event], _rules())
        if finding.rule_id == RULE_ID
    ]


def test_unnamed_run_value_matches_and_maps_to_run_keys_startup() -> None:
    matches = _matches(_event())
    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1547.001"


def test_unnamed_runonce_value_matches() -> None:
    target = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\"
    assert len(_matches(_event(target))) == 1


def test_named_run_value_does_not_match() -> None:
    target = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater"
    assert not _matches(_event(target))


def test_named_runonce_value_does_not_match() -> None:
    target = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Updater"
    assert not _matches(_event(target))


def test_similarly_named_key_does_not_match() -> None:
    target = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\"
    assert not _matches(_event(target))


def test_wrong_event_type_does_not_match() -> None:
    assert not _matches(_event(event_type="DeleteValue"))


def test_wrong_event_id_does_not_match() -> None:
    assert not _matches(_event(event_id="12"))


def test_wrong_provider_does_not_match() -> None:
    assert not _matches(_event(source="Microsoft-Windows-Security-Auditing"))
