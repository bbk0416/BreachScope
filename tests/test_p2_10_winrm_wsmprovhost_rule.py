from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]


def _rules():
    return load_rules(ROOT / "rules")


def _event(
    parent_image: str = r"C:\Windows\System32\wsmprovhost.exe",
    *,
    child_image: str = r"C:\Windows\System32\HOSTNAME.EXE",
    event_id: str = "1",
    source: str = "Microsoft-Windows-Sysmon",
) -> Event:
    return Event(
        timestamp="2026-09-09T00:00:00Z",
        host="host.example.test",
        source=source,
        event_id=event_id,
        command_line=f'"{child_image}"',
        raw={
            "ParentImage": parent_image,
            "Image": child_image,
        },
    )


def _matches(event: Event) -> list:
    return [
        finding
        for finding in apply_rules([event], _rules())
        if finding.rule_id == "R-WINRM-WSMPROVHOST-CHILD"
    ]


def test_wsmprovhost_parent_matches() -> None:
    matches = _matches(_event())
    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1021.006"


def test_wsmprovhost_parent_does_not_depend_on_child_image() -> None:
    assert len(_matches(_event(child_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))) == 1


def test_other_parent_does_not_match() -> None:
    assert not _matches(_event(parent_image=r"C:\Windows\System32\services.exe"))


def test_wrong_event_id_does_not_match() -> None:
    assert not _matches(_event(event_id="10"))


def test_wrong_provider_does_not_match() -> None:
    assert not _matches(_event(source="Microsoft-Windows-Security-Auditing"))
