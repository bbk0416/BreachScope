from __future__ import annotations

import ast
import inspect

from breachscope import correlator


def test_correlator_has_no_runtime_processed_events_exclusivity():
    source = inspect.getsource(correlator)
    tree = ast.parse(source)

    runtime_refs = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "processed_events"
    ]
    assert runtime_refs == [], (
        "processed_events still exists as a runtime symbol; event evidence can "
        "still be globally consumed by one chain."
    )


def test_p0_04_multi_membership_contract_marker_present():
    source = inspect.getsource(correlator)
    assert "BREACHSCOPE_P0_04_MULTI_MEMBERSHIP_V1" in source
    assert "evidence may participate in multiple valid chains" in source
