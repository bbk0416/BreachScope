from __future__ import annotations

from types import SimpleNamespace

from breachscope import scenario


PUBLIC_NAME = 'infer_scenarios'


def _event(host, session):
    return SimpleNamespace(
        host=host,
        raw={
            "canonical": {
                "host": {"name": host},
                "session": {"id": session},
            },
            "SubjectLogonId": session,
        },
    )


def _finding(host, session):
    return SimpleNamespace(event=_event(host, session))


def _chain(host, session):
    return SimpleNamespace(events=[_event(host, session)])


def test_scenario_scope_partitions_unrelated_hosts_and_sessions():
    a = _chain("HOST-A", "0x1")
    b = _chain("HOST-B", "0x2")
    groups = scenario._bs_p005_partition_chains([a, b])
    assert len(groups) == 2


def test_scenario_scope_keeps_related_chains_together():
    a = _chain("HOST-A", "0x1")
    b = _chain("HOST-A", "0x1")
    groups = scenario._bs_p005_partition_chains([a, b])
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_findings_from_other_host_cannot_strengthen_component():
    component = scenario._bs_p005_component_scope([_chain("HOST-A", "0x1")])
    findings = [
        _finding("HOST-A", "0x1"),
        _finding("HOST-B", "0x2"),
    ]
    selected = scenario._bs_p005_filter_findings(findings, component)
    assert len(selected) == 1
    assert scenario._bs_p005_scope(selected[0])["hosts"] == {"host-a"}


def test_same_host_different_session_is_excluded_when_session_available():
    component = scenario._bs_p005_component_scope([_chain("HOST-A", "0x1")])
    findings = [
        _finding("HOST-A", "0x1"),
        _finding("HOST-A", "0x999"),
    ]
    selected = scenario._bs_p005_filter_findings(findings, component)
    assert len(selected) == 1
    assert scenario._bs_p005_scope(selected[0])["sessions"] == {"0x1"}


def test_unscoped_finding_is_not_used_as_attack_evidence():
    component = scenario._bs_p005_component_scope([_chain("HOST-A", "0x1")])
    selected = scenario._bs_p005_filter_findings(
        [SimpleNamespace(rule_id="global-only")],
        component,
    )
    assert selected == []


def test_public_scenario_function_is_wrapped():
    public = getattr(scenario, PUBLIC_NAME)
    assert hasattr(public, "__wrapped__")
    source = open(scenario.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P0_05_SCENARIO_SCOPE_V1" in source
