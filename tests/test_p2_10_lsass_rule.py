from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]


def _rules():
    return load_rules(ROOT / "rules")


def _event(
    target_image: str = r"C:\Windows\System32\lsass.exe",
    *,
    granted_access: str = "0x00001010",
    event_id: str = "10",
    source: str = "Microsoft-Windows-Sysmon",
) -> Event:
    return Event(
        timestamp="2026-09-08T00:00:00Z",
        host="host.example.test",
        source=source,
        event_id=event_id,
        command_line="",
        raw={
            "TargetImage": target_image,
            "GrantedAccess": granted_access,
        },
    )


def _matches(event: Event) -> list:
    return [
        finding
        for finding in apply_rules([event], _rules())
        if finding.rule_id == "R-LSASS-ACCESS-1010"
    ]


def test_lsass_access_1010_matches() -> None:
    matches = _matches(_event())
    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1003.001"


def test_unpadded_1010_matches() -> None:
    assert len(_matches(_event(granted_access="0x1010"))) == 1


def test_other_lsass_access_mask_does_not_match() -> None:
    assert not _matches(_event(granted_access="0x0010"))


def test_other_target_process_does_not_match() -> None:
    assert not _matches(_event(target_image=r"C:\Windows\System32\winlogon.exe"))


def test_wrong_event_id_does_not_match() -> None:
    assert not _matches(_event(event_id="1"))


def test_wrong_provider_does_not_match() -> None:
    assert not _matches(_event(source="Microsoft-Windows-Security-Auditing"))
