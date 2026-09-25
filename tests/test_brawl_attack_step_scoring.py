from breachscope.brawl_score import (
    LEGACY_ATTACK_CROSSWALK,
    hosts_equivalent,
    referenced_event_windows,
    score_brawl_steps,
    step_window,
    technique_matches,
)
from breachscope.schemas import Event, Finding


def _finding(technique: str, host: str, timestamp: str, rule_id: str = "R-TEST") -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="test",
        severity="medium",
        mitre_technique=technique,
        event=Event(
            timestamp=timestamp,
            host=host,
            source="Microsoft-Windows-Sysmon",
            event_id="1",
            command_line="powershell.exe",
        ),
        matched_value="powershell.exe",
    )


def _step(
    technique_ids=("T1086",),
    *,
    step_id: str = "step-1",
    host: str = "host1.brawlco.com",
    time: str = "2017-02-22T18:38:14Z",
):
    return {
        "step_id": step_id,
        "techniques": [
            {
                "technique_id": technique_id,
                "technique_name": "upstream",
                "tactic": ["Execution"],
            }
            for technique_id in technique_ids
        ],
        "event_ids": ["event-1"],
        "events": [
            {
                "id": "event-1",
                "nodetype": "event",
                "host": host,
                "time": time,
            }
        ],
    }


def test_legacy_attack_crosswalk_is_frozen_for_public_brawl_techniques():
    assert LEGACY_ATTACK_CROSSWALK == {
        "T1087": "T1087",
        "T1003": "T1003",
        "T1016": "T1016",
        "T1069": "T1069",
        "T1086": "T1059.001",
        "T1060": "T1547.001",
        "T1105": "T1105",
        "T1018": "T1018",
        "T1077": "T1021.002",
        "T1047": "T1047",
    }


def test_host_matching_accepts_case_and_short_fqdn_only():
    assert hosts_equivalent("HOST1", "host1")
    assert hosts_equivalent("HOST1.", "host1")
    assert hosts_equivalent("host1", "host1.brawlco.com")
    assert not hosts_equivalent("host1.a.example", "host1.b.example")
    assert not hosts_equivalent("host1", "host2.brawlco.com")


def test_exact_bsf_time_gets_fixed_one_second_tolerance():
    windows = referenced_event_windows(_step())
    assert windows[0]["lower"].isoformat() == "2017-02-22T18:38:13+00:00"
    assert windows[0]["upper"].isoformat() == "2017-02-22T18:38:15+00:00"


def test_explicit_after_before_bounds_are_not_expanded():
    step = _step()
    step["events"][0].pop("time")
    step["events"][0]["happened_after"] = "2017-02-22T18:38:10Z"
    step["events"][0]["happened_before"] = "2017-02-22T18:38:20Z"

    lower, upper = step_window(step)

    assert lower.isoformat() == "2017-02-22T18:38:10+00:00"
    assert upper.isoformat() == "2017-02-22T18:38:20+00:00"


def test_parent_technique_accepts_current_subtechnique_but_not_reverse():
    assert technique_matches("T1003", "T1003.001")
    assert technique_matches("T1003", "T1003")
    assert not technique_matches("T1003.001", "T1003")
    assert not technique_matches("T1003", "T1059.001")


def test_pair_hit_requires_technique_host_and_same_event_time():
    step = _step()
    good = _finding("T1059.001", "HOST1", "2017-02-22T18:38:14.500000Z", "R-GOOD")
    wrong_host = _finding("T1059.001", "host2", "2017-02-22T18:38:14Z", "R-HOST")
    wrong_time = _finding("T1059.001", "host1", "2017-02-22T18:38:30Z", "R-TIME")
    wrong_technique = _finding("T1047", "host1", "2017-02-22T18:38:14Z", "R-TECH")

    result = score_brawl_steps([step], [good, wrong_host, wrong_time, wrong_technique])

    assert result["counts"]["total_step_technique_pairs"] == 1
    assert result["counts"]["pair_hits"] == 1
    assert result["counts"]["pair_misses"] == 0
    assert result["pair_rows"][0]["status"] == "HIT"
    assert [item["rule_id"] for item in result["pair_rows"][0]["matching_findings"]] == ["R-GOOD"]
    assert result["step_rows"][0]["status"] == "HIT"


def test_host_and_time_are_coupled_to_same_referenced_event():
    step = _step()
    step["events"] = [
        {
            "id": "event-a",
            "nodetype": "event",
            "host": "host-a.brawlco.com",
            "time": "2017-02-22T18:00:00Z",
        },
        {
            "id": "event-b",
            "nodetype": "event",
            "host": "host-b.brawlco.com",
            "time": "2017-02-22T19:00:00Z",
        },
    ]
    cross_combined = _finding(
        "T1059.001",
        "host-a.brawlco.com",
        "2017-02-22T19:00:00Z",
    )

    result = score_brawl_steps([step], [cross_combined])

    assert result["pair_rows"][0]["status"] == "MISS"


def test_multi_technique_step_is_partial_when_only_one_pair_hits():
    step = _step(("T1086", "T1047"))
    finding = _finding("T1059.001", "host1", "2017-02-22T18:38:14Z")

    result = score_brawl_steps([step], [finding])

    assert result["counts"]["total_step_technique_pairs"] == 2
    assert result["counts"]["pair_hits"] == 1
    assert result["counts"]["pair_misses"] == 1
    assert result["step_rows"][0]["status"] == "PARTIAL"
    assert result["step_technique_hit_fraction_of_all_pairs"] == 0.5


def test_pair_miss_is_not_called_recall():
    result = score_brawl_steps([_step()], [])

    assert result["metric_name"] == "brawl_attack_step_technique_hit_fraction"
    assert result["pair_rows"][0]["status"] == "MISS"
    assert result["step_technique_hit_fraction_of_all_pairs"] == 0.0
    assert result["claim_boundaries"]["event_level_recall"] == "NOT_CLAIMED"
    assert result["claim_boundaries"]["false_positive_rate"] == "NOT_CLAIMED"


def test_unmapped_upstream_technique_is_error_not_miss():
    result = score_brawl_steps([_step(("T9999",))], [])

    assert result["counts"]["pair_errors"] == 1
    assert result["counts"]["pair_misses"] == 0
    assert result["pair_rows"][0]["status"] == "ERROR"
    assert "unmapped upstream" in result["pair_rows"][0]["error"]
    assert result["step_rows"][0]["status"] == "ERROR"


def test_missing_referenced_event_host_is_error_not_miss():
    result = score_brawl_steps([_step(host="")], [])

    assert result["counts"]["pair_errors"] == 1
    assert result["pair_rows"][0]["status"] == "ERROR"
    assert "host" in result["pair_rows"][0]["error"]


def test_parent_brawl_label_can_match_current_specific_finding():
    step = _step(("T1003",))
    finding = _finding("T1003.001", "host1.brawlco.com", "2017-02-22T18:38:14Z")

    result = score_brawl_steps([step], [finding])

    assert result["pair_rows"][0]["status"] == "HIT"
