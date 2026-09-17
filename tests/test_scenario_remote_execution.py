from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from breachscope import scenario


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event(host: str):
    return SimpleNamespace(host=host)


def _finding(host: str, severity: str = "high", technique: str = "T1569.002"):
    return SimpleNamespace(
        event=_event(host),
        severity=severity,
        mitre_technique=technique,
    )


def _chain(
    chain_id: str,
    start: datetime,
    findings,
    hosts=("HOST-A", "HOST-B"),
    confidence: float = 1.0,
    method: str = "psexec",
):
    return SimpleNamespace(
        chain_id=chain_id,
        chain_type="remote_execution",
        events=[_event(host) for host in hosts],
        findings=list(findings),
        start_time=start,
        end_time=start + timedelta(seconds=30),
        description=f"remote {hosts[0]} -> {hosts[1]}",
        confidence=confidence,
        metadata={
            "remote_execution": {
                "source_host": hosts[0],
                "target_host": hosts[1],
                "method": method,
            }
        },
    )


def _bilateral(severity: str = "high", technique: str = "T1569.002"):
    return [
        _finding("HOST-A", severity=severity, technique=technique),
        _finding("HOST-B", severity=severity, technique=technique),
    ]


def test_bilateral_high_remote_execution_creates_lateral_scenario():
    scenarios = scenario.infer_scenarios(
        [_chain("remote_1", BASE, _bilateral())], []
    )
    assert len(scenarios) == 1
    result = scenarios[0]
    assert result.attack_stage == "lateral_movement"
    assert result.mitre_techniques == ["T1569.002"]
    assert len(result.chains) == 1
    assert result.confidence == 0.9


def test_unilateral_high_finding_does_not_create_remote_scenario():
    chain = _chain("remote_1", BASE, [_finding("HOST-A")])
    assert scenario.infer_scenarios([chain], []) == []


def test_bilateral_medium_findings_do_not_create_remote_scenario():
    chain = _chain("remote_1", BASE, _bilateral(severity="medium"))
    assert scenario.infer_scenarios([chain], []) == []


def test_repeated_remote_chains_same_pair_group_into_one_episode():
    chains = [
        _chain(f"remote_{i}", BASE + timedelta(minutes=i), _bilateral())
        for i in range(4)
    ]
    scenarios = scenario.infer_scenarios(chains, [])
    assert len(scenarios) == 1
    assert len(scenarios[0].chains) == 4


def test_distant_remote_chains_same_pair_split_into_two_episodes():
    chains = [
        _chain("remote_1", BASE, _bilateral()),
        _chain("remote_2", BASE + timedelta(minutes=10), _bilateral()),
    ]
    scenarios = scenario.infer_scenarios(chains, [])
    assert len(scenarios) == 2
    assert sorted(len(item.chains) for item in scenarios) == [1, 1]


def test_different_host_pairs_never_merge():
    first = _chain("remote_1", BASE, _bilateral())
    second = _chain(
        "remote_2",
        BASE + timedelta(minutes=1),
        [_finding("HOST-C"), _finding("HOST-D")],
        hosts=("HOST-C", "HOST-D"),
    )
    scenarios = scenario.infer_scenarios([first, second], [])
    assert len(scenarios) == 2
    assert sorted(len(item.chains) for item in scenarios) == [1, 1]


def test_finding_on_unrelated_host_cannot_complete_bilateral_evidence():
    chain = _chain(
        "remote_1",
        BASE,
        [_finding("HOST-A"), _finding("HOST-C")],
    )
    assert scenario.infer_scenarios([chain], []) == []


def test_bilateral_high_unrelated_technique_does_not_create_remote_scenario():
    chain = _chain("remote_1", BASE, _bilateral(technique="T1003.001"))
    assert scenario.infer_scenarios([chain], []) == []


def test_mismatched_remote_techniques_across_hosts_do_not_promote():
    chain = _chain(
        "remote_1",
        BASE,
        [
            _finding("HOST-A", technique="T1569.002"),
            _finding("HOST-B", technique="T1021.006"),
        ],
    )
    assert scenario.infer_scenarios([chain], []) == []


def test_bilateral_high_winrm_technique_can_promote():
    chain = _chain(
        "remote_1", BASE, _bilateral(technique="T1021.006"), method="powershell"
    )
    result = scenario.infer_scenarios([chain], [])
    assert len(result) == 1
    assert result[0].mitre_techniques == ["T1021.006"]


def test_method_technique_mismatch_does_not_promote():
    chain = _chain(
        "remote_1", BASE, _bilateral(technique="T1021.006"), method="psexec"
    )
    assert scenario.infer_scenarios([chain], []) == []


def test_opposite_directions_for_same_host_pair_do_not_merge():
    forward = _chain("remote_1", BASE, _bilateral(), hosts=("HOST-A", "HOST-B"))
    reverse = _chain(
        "remote_2",
        BASE + timedelta(minutes=1),
        _bilateral(),
        hosts=("HOST-B", "HOST-A"),
    )
    scenarios = scenario.infer_scenarios([forward, reverse], [])
    assert len(scenarios) == 2
    assert sorted(len(item.chains) for item in scenarios) == [1, 1]


def test_different_remote_techniques_same_direction_do_not_merge():
    psexec = _chain("remote_1", BASE, _bilateral(technique="T1569.002"))
    winrm = _chain(
        "remote_2",
        BASE + timedelta(minutes=1),
        _bilateral(technique="T1021.006"),
        method="powershell",
    )
    scenarios = scenario.infer_scenarios([psexec, winrm], [])
    assert len(scenarios) == 2
    assert sorted(tuple(item.mitre_techniques) for item in scenarios) == [
        ("T1021.006",),
        ("T1569.002",),
    ]


def test_scm_remote_service_chain_is_descriptive_only_for_now():
    chain = _chain(
        "remote_1",
        BASE,
        _bilateral(technique="T1569.002"),
        method="scm",
    )
    assert scenario.infer_scenarios([chain], []) == []
