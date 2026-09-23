from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from breachscope.analyzer import apply_rules
from breachscope.canonical import build_canonical_event
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
RULE_ID = "R-MASQUERADE-ORIGINAL-NAME-MISMATCH"


def _candidate_rule():
    by_id = {rule.id: rule for rule in load_rules(ROOT / "rules")}
    return by_id[RULE_ID]


def _event(
    *,
    executable: str = r"C:\Windows\renamed.exe",
    original_file_name: str | None = "original.exe",
    parent: str = r"C:\Windows\System32\cmd.exe",
    source: str = "Microsoft-Windows-Sysmon",
    event_id: str = "1",
) -> Event:
    raw = {
        "canonical": {
            "process": {
                "executable": executable,
                "parent_executable": parent,
            }
        }
    }
    if original_file_name is not None:
        raw["OriginalFileName"] = original_file_name
    return Event(
        timestamp="2026-09-24T00:00:00Z",
        host="WIN-TEST",
        source=source,
        event_id=event_id,
        user="tester",
        command_line=f'"{executable}"',
        raw=raw,
    )


def test_p2_35i_ecs_process_fallback_populates_canonical_process() -> None:
    event = {
        "event_id": 1,
        "source": "Microsoft-Windows-Sysmon",
        "host": "WIN-A",
        "raw": {
            "process": {
                "executable": r"C:\Windows\renamed.exe",
                "parent": {
                    "executable": r"C:\Windows\System32\cmd.exe",
                },
            },
            "event_data": {
                "OriginalFileName": "original.exe",
            },
        },
    }
    canonical = build_canonical_event(event)
    assert canonical["process"]["executable"] == r"C:\Windows\renamed.exe"
    assert canonical["process"]["parent_executable"] == r"C:\Windows\System32\cmd.exe"


def test_p2_35i_legacy_process_fields_take_precedence_over_ecs_fallback() -> None:
    event = {
        "event_id": 1,
        "source": "Microsoft-Windows-Sysmon",
        "host": "WIN-A",
        "raw": {
            "process": {
                "executable": r"C:\Windows\ecs.exe",
                "parent": {
                    "executable": r"C:\Windows\System32\ecs-parent.exe",
                },
            },
            "event_data": {
                "Image": r"C:\Windows\legacy.exe",
                "ParentImage": r"C:\Windows\System32\legacy-parent.exe",
            },
        },
    }
    canonical = build_canonical_event(event)
    assert canonical["process"]["executable"] == r"C:\Windows\legacy.exe"
    assert canonical["process"]["parent_executable"] == (
        r"C:\Windows\System32\legacy-parent.exe"
    )


def test_p2_35i_rule_matches_source_independent_socbed_shape() -> None:
    rule = _candidate_rule()
    event = _event(
        executable=r"C:\Windows\renamed_payload.exe",
        original_file_name="ab.exe",
        parent=r"C:\Windows\System32\cmd.exe",
    )
    findings = list(apply_rules([event], [rule]))
    assert len(findings) == 1
    assert findings[0].rule_id == RULE_ID
    assert findings[0].mitre_technique == "T1036.003"


@pytest.mark.parametrize(
    ("event", "reason"),
    [
        (_event(original_file_name="renamed.exe"), "equal basename"),
        (_event(original_file_name="RENAMED.EXE"), "case-insensitive equal basename"),
        (_event(original_file_name=None), "missing original file name"),
        (
            _event(parent=r"C:\Windows\explorer.exe"),
            "parent outside preregistered command interpreters",
        ),
        (
            _event(executable=r"C:\Windows\System32\renamed.exe"),
            "location outside preregistered suspicious locations",
        ),
        (_event(source="Other-Provider"), "wrong provider"),
        (_event(event_id="3"), "wrong event id"),
    ],
)
def test_p2_35i_rule_fails_closed_outside_exact_predicate(
    event: Event, reason: str
) -> None:
    assert list(apply_rules([event], [_candidate_rule()])) == [], reason


def test_p2_35i_field_compare_operator_is_all_of_only(tmp_path: Path) -> None:
    bad = {
        "id": "BAD-BASENAME-COMPARE",
        "name": "bad",
        "description": "top-level field compare must remain unsupported",
        "field": "canonical.process.executable",
        "operator": "basename_not_equals_field",
        "pattern": "OriginalFileName",
    }
    (tmp_path / "bad.yml").write_text(
        yaml.safe_dump(bad, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported native operator"):
        load_rules(tmp_path)


def test_p2_35i_rule_contains_no_source_specific_socbed_literals() -> None:
    text = (ROOT / "rules" / "p2_10_event_rules.yml").read_text(encoding="utf-8")
    block = text.split(f"- id: {RULE_ID}", 1)[1]
    forbidden = (
        "meterpreter",
        "meterpreter_bind_tcp.exe",
        "a14c7b38ef660603c792da24543524dada182c7b11fb8a354fa436d2401aace5",
        "CLIENT1",
        "CLIENT1\\ssh",
    )
    lowered = block.casefold()
    for token in forbidden:
        assert token.casefold() not in lowered
