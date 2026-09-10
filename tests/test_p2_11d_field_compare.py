from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


def _event(*, left: str | None, right: str | None, host: str = "WS-01") -> Event:
    raw = {}
    if left is not None:
        raw["Left"] = left
    if right is not None:
        raw["Right"] = right
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host=host,
        source="Test",
        event_id="1",
        user="",
        command_line="",
        raw=raw,
    )


def _write_field_compare_rule(path: Path, *, right_field: str = "Right") -> None:
    doc = {
        "id": "FIELD-COMPARE",
        "name": "field compare",
        "description": "test",
        "field": "event_id",
        "operator": "equals",
        "pattern": "1",
        "all_of": [
            {
                "field": "Left",
                "operator": "equals_field",
                "pattern": right_field,
            }
        ],
    }
    path.write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )


def test_equals_field_matches_case_insensitively(tmp_path: Path) -> None:
    _write_field_compare_rule(tmp_path / "rule.yml")
    rule = load_rules(tmp_path)[0]
    event = _event(left="Server002", right="SERVER002")
    assert len(list(apply_rules([event], [rule]))) == 1


def test_equals_field_rejects_different_values(tmp_path: Path) -> None:
    _write_field_compare_rule(tmp_path / "rule.yml")
    rule = load_rules(tmp_path)[0]
    event = _event(left="Server002", right="DOMAIN01")
    assert list(apply_rules([event], [rule])) == []


def test_equals_field_missing_referenced_field_fails_closed(tmp_path: Path) -> None:
    _write_field_compare_rule(tmp_path / "rule.yml")
    rule = load_rules(tmp_path)[0]
    event = _event(left="Server002", right=None)
    assert list(apply_rules([event], [rule])) == []


def test_host_field_comparison_accepts_short_name_for_fqdn(tmp_path: Path) -> None:
    _write_field_compare_rule(tmp_path / "rule.yml", right_field="host")
    rule = load_rules(tmp_path)[0]
    event = _event(
        left="SERVER002",
        right=None,
        host="server002.example.corp",
    )
    assert len(list(apply_rules([event], [rule]))) == 1


def test_host_field_comparison_rejects_different_host(tmp_path: Path) -> None:
    _write_field_compare_rule(tmp_path / "rule.yml", right_field="host")
    rule = load_rules(tmp_path)[0]
    event = _event(
        left="DOMAIN01",
        right=None,
        host="server002.example.corp",
    )
    assert list(apply_rules([event], [rule])) == []


def test_equals_field_is_not_allowed_as_top_level_operator(tmp_path: Path) -> None:
    doc = {
        "id": "BAD-TOPLEVEL-FIELD-COMPARE",
        "name": "bad",
        "description": "test",
        "field": "Left",
        "operator": "equals_field",
        "pattern": "Right",
    }
    (tmp_path / "bad.yml").write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match=r"unsupported native operator",
    ):
        load_rules(tmp_path)
