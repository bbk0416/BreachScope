from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


RULE_ID = "R-RDP-CLIENT-MSTSC-V"


def _rule():
    by_id = {rule.id: rule for rule in load_rules(Path("rules"))}
    return by_id[RULE_ID]


def _event(
    *,
    image: str = r"C:\Windows\System32\mstsc.exe",
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


def test_atomic_style_rdp_target_matches() -> None:
    assert _ids(_event(command_line="mstsc.exe /v:server01")) == {RULE_ID}


def test_hostname_with_port_matches() -> None:
    assert _ids(_event(command_line="mstsc /v:server01:3390")) == {RULE_ID}


def test_quoted_target_matches() -> None:
    assert _ids(_event(command_line='mstsc.exe /v:"server01.example.test"')) == {RULE_ID}


def test_case_and_spacing_variation_matches() -> None:
    assert _ids(_event(command_line="MSTSC.EXE /V : server01")) == {RULE_ID}


def test_admin_modifier_with_target_still_matches() -> None:
    assert _ids(_event(command_line="mstsc.exe /admin /v:server01")) == {RULE_ID}


def test_plain_mstsc_is_excluded() -> None:
    assert _ids(_event(command_line="mstsc.exe")) == set()


def test_empty_target_is_excluded() -> None:
    assert _ids(_event(command_line="mstsc.exe /v:   ")) == set()


def test_similar_switch_is_excluded() -> None:
    assert _ids(_event(command_line="mstsc.exe /view:server01")) == set()


def test_non_mstsc_image_is_excluded() -> None:
    assert _ids(_event(image=r"C:\Windows\System32\cmd.exe", command_line="mstsc.exe /v:server01")) == set()


def test_wrong_provider_is_excluded() -> None:
    assert _ids(_event(command_line="mstsc.exe /v:server01", source="Microsoft-Windows-Security-Auditing")) == set()


def test_wrong_event_id_is_excluded() -> None:
    assert _ids(_event(command_line="mstsc.exe /v:server01", event_id="13")) == set()


def test_rule_metadata_is_low_confidence_generic_rdp_telemetry() -> None:
    rule = _rule()
    assert rule.mitre_technique == "T1021.001"
    assert rule.severity == "low"
    text = " ".join([rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)]).lower()
    assert "domaincontroller" not in text
    assert "atomic" not in text
    assert "cmdkey" not in text
    assert "admin_test" not in text
    assert "completed session" in rule.description.lower()
