from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
RULE_ID = "R-SERVICE-PATHLESS-7045"


def _rules():
    return load_rules(ROOT / "rules")


def _event(
    image_path: str = "cmd.exe",
    *,
    event_id: str = "7045",
    source: str = "Service Control Manager",
) -> Event:
    return Event(
        timestamp="2026-09-10T00:00:00Z",
        host="host.example.test",
        source=source,
        event_id=event_id,
        command_line="",
        raw={
            "ImagePath": image_path,
            "ServiceName": "arbitrary-service",
        },
    )


def _matches(event: Event) -> list:
    return [
        finding
        for finding in apply_rules([event], _rules())
        if finding.rule_id == RULE_ID
    ]


def test_pathless_executable_matches_and_maps_to_service_execution() -> None:
    matches = _matches(_event("cmd.exe"))
    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1569.002"


def test_pathless_executable_with_arguments_matches() -> None:
    assert len(_matches(_event("cmd.exe /c whoami"))) == 1


def test_quoted_pathless_executable_matches() -> None:
    assert len(_matches(_event('"calc.exe"'))) == 1


def test_absolute_path_does_not_match() -> None:
    assert not _matches(_event(r"C:\Windows\System32\cmd.exe"))


def test_quoted_absolute_path_does_not_match() -> None:
    assert not _matches(_event(r'"C:\Windows\System32\cmd.exe" /c whoami'))


def test_unc_path_does_not_match() -> None:
    assert not _matches(_event(r"\\server\share\svc.exe"))


def test_wrong_event_id_does_not_match() -> None:
    assert not _matches(_event(event_id="7040"))


def test_wrong_provider_does_not_match() -> None:
    assert not _matches(_event(source="Microsoft-Windows-Security-Auditing"))
