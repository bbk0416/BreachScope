from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from breachscope.analyzer import apply_rules, apply_rules_parallel
from breachscope.rules import load_rules
from breachscope.schemas import Event, Rule


def _event(*, source: str, event_id: str, command_line: str = "") -> Event:
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="WS-01",
        source=source,
        event_id=event_id,
        user="",
        command_line=command_line,
    )


def _audit_rule(event_id: str = "104") -> Rule:
    return Rule(
        id=f"TEST-AUDIT-{event_id}",
        name="Windows event-log clear audit",
        description="test",
        field="event_id",
        operator="equals",
        pattern=event_id,
        severity="high",
        mitre_technique="T1070.001",
        all_of=[
            {
                "field": "source",
                "operator": "equals",
                "pattern": "Microsoft-Windows-Eventlog",
            }
        ],
    )


def test_primary_rule_field_is_actually_evaluated() -> None:
    rule = Rule(
        id="PRIMARY-SOURCE",
        name="primary source",
        description="test",
        field="source",
        operator="equals",
        pattern="Microsoft-Windows-Eventlog",
        severity="medium",
    )
    hit = _event(source="Microsoft-Windows-Eventlog", event_id="104")
    miss = _event(source="ProcessCreate", event_id="104")

    findings = list(apply_rules([hit, miss], [rule]))
    assert len(findings) == 1
    assert findings[0].event.source == "Microsoft-Windows-Eventlog"


def test_all_of_requires_primary_match_and_every_condition() -> None:
    rule = _audit_rule("104")

    hit = _event(source="Microsoft-Windows-Eventlog", event_id="104")
    wrong_source = _event(source="ProcessCreate", event_id="104")
    wrong_event = _event(source="Microsoft-Windows-Eventlog", event_id="4688")

    assert len(list(apply_rules([hit], [rule]))) == 1
    assert list(apply_rules([wrong_source], [rule])) == []
    assert list(apply_rules([wrong_event], [rule])) == []


def test_all_of_uses_existing_case_insensitive_equals_matcher() -> None:
    rule = _audit_rule("104")
    event = _event(source="microsoft-windows-eventlog", event_id="104")
    assert len(list(apply_rules([event], [rule]))) == 1


def test_legacy_command_line_rule_result_is_preserved() -> None:
    rule = Rule(
        id="LEGACY",
        name="legacy command line",
        description="test",
        field="command_line",
        operator="contains",
        pattern="wevtutil cl",
        severity="high",
        mitre_technique="T1070.001",
    )
    event = _event(
        source="ProcessCreate",
        event_id="4688",
        command_line="wevtutil cl Security",
    )
    findings = list(apply_rules([event], [rule]))
    assert len(findings) == 1
    assert findings[0].matched_value.lower() == "wevtutil cl"


def test_parallel_analyzer_uses_primary_field_and_all_of() -> None:
    rule = _audit_rule("104")
    events = [
        _event(source="Microsoft-Windows-Eventlog", event_id="104"),
        _event(source="ProcessCreate", event_id="104"),
        _event(source="Microsoft-Windows-Eventlog", event_id="4688"),
    ]
    findings = apply_rules_parallel(events, [rule], max_workers=1, chunk_size=10)
    assert len(findings) == 1
    assert findings[0].event.source == "Microsoft-Windows-Eventlog"
    assert findings[0].event.event_id == "104"


def test_native_yaml_loader_round_trips_all_of_and_rejects_malformed(tmp_path: Path) -> None:
    doc = [
        {
            "id": "VALID-ALLOF",
            "name": "valid",
            "description": "test",
            "field": "event_id",
            "operator": "equals",
            "pattern": "104",
            "severity": "high",
            "mitre_technique": "T1070.001",
            "all_of": [
                {
                    "field": "source",
                    "operator": "equals",
                    "pattern": "Microsoft-Windows-Eventlog",
                }
            ],
        },
        {
            "id": "INVALID-ALLOF",
            "name": "invalid",
            "description": "test",
            "field": "event_id",
            "operator": "equals",
            "pattern": "104",
            "severity": "high",
            "all_of": [{"field": "source", "operator": "equals"}],
        },
    ]
    (tmp_path / "rules.yml").write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=r"rules\.yml\[2\].*requires field and pattern",
    ):
        load_rules(tmp_path)


def test_project_rulepack_preserves_execution_rule_and_adds_guarded_audit_rules() -> None:
    rules = load_rules(Path("rules"))
    by_id = {r.id: r for r in rules}

    original = by_id["R-EVENTLOG-Clear"]
    assert original.field == "command_line"
    assert original.pattern == "wevtutil cl|Clear-EventLog|Remove-EventLog"
    assert original.all_of is None

    for event_id in ("104", "1102"):
        rule = by_id[f"R-EVENTLOG-Clear-Audit-{event_id}"]
        assert rule.field == "event_id"
        assert rule.operator == "equals"
        assert rule.pattern == event_id
        assert rule.mitre_technique == "T1070.001"
        assert rule.all_of == [
            {
                "field": "source",
                "operator": "equals",
                "pattern": "Microsoft-Windows-Eventlog",
            }
        ]


def test_event_id_only_context_does_not_trigger_audit_rules() -> None:
    rules = [
        r
        for r in load_rules(Path("rules"))
        if r.id.startswith("R-EVENTLOG-Clear-Audit-")
    ]
    event = _event(source="ProcessCreate", event_id="104")
    assert list(apply_rules([event], rules)) == []


def test_native_yaml_loader_round_trips_valid_all_of(tmp_path: Path) -> None:
    doc = {
        "id": "VALID-ALLOF",
        "name": "valid",
        "description": "test",
        "field": "event_id",
        "operator": "equals",
        "pattern": "104",
        "severity": "high",
        "mitre_technique": "T1070.001",
        "all_of": [
            {
                "field": "source",
                "operator": "equals",
                "pattern": "Microsoft-Windows-Eventlog",
            }
        ],
    }
    (tmp_path / "valid.yml").write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )
    rules = load_rules(tmp_path)
    assert [rule.id for rule in rules] == ["VALID-ALLOF"]
    assert rules[0].all_of == doc["all_of"]


def test_native_loader_rejects_missing_required_fields_instead_of_skipping(
    tmp_path: Path,
) -> None:
    doc = [
        {
            "id": "VALID",
            "name": "valid",
            "operator": "contains",
            "pattern": "powershell",
        },
        {
            "id": "MISSING-PATTERN",
            "name": "invalid",
            "operator": "contains",
        },
    ]
    (tmp_path / "mixed.yml").write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"mixed\.yml\[2\].*pattern"):
        load_rules(tmp_path)


def test_native_loader_rejects_invalid_regex_during_load(tmp_path: Path) -> None:
    doc = {
        "id": "BAD-REGEX",
        "name": "bad regex",
        "operator": "regex",
        "pattern": "[",
    }
    (tmp_path / "bad_regex.yml").write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match=r"bad_regex\.yml\[1\].*failed validation",
    ):
        load_rules(tmp_path)


def test_native_loader_rejects_unsupported_operator(tmp_path: Path) -> None:
    doc = {
        "id": "BAD-OP",
        "name": "bad operator",
        "operator": "glob",
        "pattern": "powershell*",
    }
    (tmp_path / "bad_operator.yml").write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match=r"bad_operator\.yml\[1\].*unsupported native operator",
    ):
        load_rules(tmp_path)


def test_nested_malformed_yaml_fails_closed_instead_of_being_skipped(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "broken.yml").write_text("id: [unterminated", encoding="utf-8")
    with pytest.raises(ValueError, match=r"broken\.yml.*YAML parse failed"):
        load_rules(tmp_path)


def test_empty_rule_directory_still_uses_legacy_defaults(tmp_path: Path) -> None:
    rules = load_rules(tmp_path)
    assert [rule.id for rule in rules] == ["R-ENC", "R-DL"]
