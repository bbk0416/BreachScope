from __future__ import annotations

from types import SimpleNamespace

from breachscope import correlator


def _event(source, event_id, category, action, provider):
    return SimpleNamespace(
        source=source,
        event_id=event_id,
        host="WIN-A",
        user="alice",
        command_line="",
        raw={
            "canonical": {
                "event": {
                    "category": category,
                    "action": action,
                    "provider": provider,
                    "code": event_id,
                },
                "host": {"name": "WIN-A"},
            }
        },
    )


def test_real_security_4688_matches_legacy_processcreate_source():
    event = _event(
        "Microsoft-Windows-Security-Auditing",
        "4688",
        "process",
        "process_start",
        "windows.security",
    )
    assert correlator._match_event_pattern(event, ["source:ProcessCreate"])


def test_real_sysmon_1_matches_legacy_processcreate_source():
    event = _event(
        "Microsoft-Windows-Sysmon",
        "1",
        "process",
        "process_start",
        "windows.sysmon",
    )
    assert correlator._match_event_pattern(event, ["source:ProcessCreate"])


def test_sysmon_network_event_does_not_match_processcreate():
    event = _event(
        "Microsoft-Windows-Sysmon",
        "3",
        "network",
        "connection",
        "windows.sysmon",
    )
    assert not correlator._match_event_pattern(event, ["source:ProcessCreate"])


def test_canonical_provider_is_directly_matchable():
    event = _event(
        "Microsoft-Windows-Sysmon",
        "1",
        "process",
        "process_start",
        "windows.sysmon",
    )
    assert correlator._match_event_pattern(event, ["source:windows.sysmon"])


def test_canonical_action_is_directly_matchable():
    event = _event(
        "Microsoft-Windows-Sysmon",
        "1",
        "process",
        "process_start",
        "windows.sysmon",
    )
    assert correlator._match_event_pattern(event, ["source:process_start"])


def test_legacy_processcreate_source_still_matches_without_canonical_data():
    event = SimpleNamespace(
        source="ProcessCreate",
        event_id="1",
        host="WIN-A",
        user="alice",
        command_line="",
        raw={},
    )
    assert correlator._match_event_pattern(event, ["source:ProcessCreate"])


def test_event_id_and_command_line_legacy_matching_still_work():
    event = SimpleNamespace(
        source="Microsoft-Windows-Security-Auditing",
        event_id="4688",
        host="WIN-A",
        user="alice",
        command_line="powershell.exe -NoProfile",
        raw={},
    )
    assert correlator._match_event_pattern(event, ["event_id:4688"])
    assert correlator._match_event_pattern(event, ["cmd:powershell"])


def test_unrelated_source_is_not_broadened_by_canonical_bridge():
    event = _event(
        "Microsoft-Windows-Sysmon",
        "3",
        "network",
        "connection",
        "windows.sysmon",
    )
    assert not correlator._match_event_pattern(event, ["source:PowerShell"])
    assert not correlator._match_event_pattern(event, ["source:ProcessCreate"])


def test_p0_07_marker_and_single_core_helper_definitions_are_present():
    import ast
    from pathlib import Path

    source = Path(correlator.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    expected = {"_match_event_pattern", "_extract_common_key"}
    counts = {name: 0 for name in expected}
    for node in tree.body:
        name = getattr(node, "name", None)
        if name in counts:
            counts[name] += 1

    assert "BREACHSCOPE_P0_07_CANONICAL_SOURCE_BRIDGE_V1" in source
    assert "BREACHSCOPE_P0_03_REQUIRED_FIELDS_AND_V1" in source
    assert counts == {name: 1 for name in expected}
    assert "_match_event_pattern_p0_06" not in source
    assert "_extract_common_key_p0_02" not in source
