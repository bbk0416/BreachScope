from __future__ import annotations

import importlib.util
from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.attack_annotations import attack_requirement_satisfied
from breachscope.rules import load_rules
from breachscope.schemas import Event
from breachscope.scenario import _bs_p006_attack_requirement_satisfied

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_external_holdout.py"
SPEC = importlib.util.spec_from_file_location("p2_11g_external_holdout", SCRIPT)
assert SPEC and SPEC.loader
holdout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(holdout)


def _encoded_event(command_line: str) -> Event:
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="WS-01",
        source="Microsoft-Windows-Sysmon",
        event_id="1",
        user="CORP\\alice",
        command_line=command_line,
        raw={"CommandLine": command_line},
    )


def _r_enc():
    return next(rule for rule in load_rules(ROOT / "rules") if rule.id == "R-ENC")


def test_r_enc_keeps_primary_mapping_and_adds_command_obfuscation():
    rule = _r_enc()
    assert rule.mitre_technique == "T1059.001"
    assert rule.mitre_techniques == ["T1059.001", "T1027.010"]
    assert rule.field == "command_line"
    assert rule.operator == "contains"
    assert rule.pattern == "-encodedcommand|-enc"


def test_r_enc_emits_one_finding_with_both_techniques():
    rule = _r_enc()
    event = _encoded_event("powershell.exe -EncodedCommand SQBFAFgA")
    findings = list(apply_rules([event], [rule]))
    assert len(findings) == 1
    assert findings[0].rule_id == "R-ENC"
    assert findings[0].mitre_technique == "T1059.001"
    assert findings[0].mitre_techniques == ["T1059.001", "T1027.010"]


def test_r_enc_still_does_not_match_unencoded_powershell():
    rule = _r_enc()
    event = _encoded_event("powershell.exe Get-Process")
    assert list(apply_rules([event], [rule])) == []


def test_external_evaluator_accepts_parent_requirement_from_child_mapping():
    manifest = {
        "scenarios": [
            {
                "scenario_id": "T1027-2",
                "source_files": ["attack.jsonl"],
                "expected_techniques": ["T1027"],
            }
        ]
    }
    records = [{"event_key": "a" * 64, "source_file": "attack.jsonl"}]
    result = holdout.scenario_outcomes(
        manifest,
        records,
        {"a" * 64: {"T1059.001", "T1027.010"}},
    )
    assert result["hits"] == 1
    assert result["misses"] == 0
    row = result["outcomes"][0]
    assert row["matched_techniques"] == ["T1027"]
    assert row["missing_techniques"] == []
    assert row["observed_techniques"] == ["T1027.010", "T1059.001"]


def test_attack_hierarchy_does_not_match_siblings_or_parent_to_child_reverse():
    assert attack_requirement_satisfied("T1027", "T1027.010")
    assert not attack_requirement_satisfied("T1021.001", "T1021.006")
    assert not attack_requirement_satisfied("T1027.010", "T1027")
    assert not attack_requirement_satisfied("invalid", "T1027.010")


def test_external_and_internal_attack_hierarchy_contracts_stay_aligned():
    cases = [
        ("T1027", "T1027", True),
        ("T1027", "T1027.010", True),
        ("T1021.001", "T1021.006", False),
        ("T1027.010", "T1027", False),
        ("invalid", "T1027.010", False),
    ]
    for required, observed, expected in cases:
        assert attack_requirement_satisfied(required, observed) is expected
        assert _bs_p006_attack_requirement_satisfied(required, observed) is expected


def test_evaluator_collects_plural_finding_techniques_without_duplicate_findings():
    rule = _r_enc()
    event = _encoded_event("powershell.exe -enc SQBFAFgA")
    findings = list(apply_rules([event], [rule]))
    assert len(findings) == 1
    assert holdout._finding_techniques(findings[0]) == {"T1059.001", "T1027.010"}
