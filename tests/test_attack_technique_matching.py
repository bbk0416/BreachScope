from __future__ import annotations

import ast
import inspect

from breachscope import scenario


def test_attack_exact_subtechnique_matches():
    assert scenario._bs_p006_attack_requirement_satisfied("T1059.001", "T1059.001")


def test_attack_sibling_subtechnique_does_not_match():
    assert not scenario._bs_p006_attack_requirement_satisfied("T1059.001", "T1059.003")
    assert not scenario._bs_p006_attack_requirement_satisfied("T1003.001", "T1003.006")


def test_attack_parent_requirement_accepts_child():
    assert scenario._bs_p006_attack_requirement_satisfied("T1059", "T1059.001")
    assert scenario._bs_p006_attack_requirement_satisfied("t1003", "T1003.006")


def test_attack_child_requirement_does_not_accept_parent():
    assert not scenario._bs_p006_attack_requirement_satisfied("T1059.001", "T1059")


def test_attack_unrelated_and_invalid_ids_do_not_match():
    assert not scenario._bs_p006_attack_requirement_satisfied("T1059", "T1003.001")
    assert not scenario._bs_p006_attack_requirement_satisfied("powershell", "powershell")
    assert not scenario._bs_p006_attack_requirement_satisfied("", "T1059")
    assert not scenario._bs_p006_attack_requirement_satisfied(None, "T1059")


def test_scenario_source_uses_p006_match_helper():
    source = inspect.getsource(scenario)
    assert "BREACHSCOPE_P0_06_ATTACK_MATCH_V1" in source
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_bs_p006_attack_requirement_satisfied"
    ]
    assert calls, "Scenario inference does not call the precise ATT&CK matcher."
