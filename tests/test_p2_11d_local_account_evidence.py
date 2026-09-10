from __future__ import annotations

import json
from pathlib import Path

import yaml


PATH = Path("external_baseline/p2_11d_local_account_calibration.json")
MEASUREMENT = Path("external_baseline/results/p2_11d_456b2a82/measurement.yaml")
AGGREGATE = Path("external_baseline/results/p2_11d_456b2a82/aggregate-result.json")


def _record():
    return json.loads(PATH.read_text(encoding="utf-8"))


def test_p2_11d_evidence_locks_pinned_sources_and_counts() -> None:
    record = _record()
    benign = record["benign_probe"]
    attack = record["attack_probe"]

    assert benign["asset_sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert benign["evtx_files"] == 352
    assert benign["non_sysmon_events"] == 34423
    assert benign["parse_errors"] == 0
    assert benign["security_4720_events"] == 3
    assert benign["candidate_matches"] == 0

    assert attack["pinned_commit"] == (
        "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
    )
    assert attack["parsed_security_events"] == 26
    assert attack["parse_errors"] == 0
    assert attack["security_4720_events"] == 2
    assert attack["candidate_matches"] == 2


def test_p2_11d_calibration_score_is_locked() -> None:
    score = _record()["calibration_score"]

    assert score["historical_p2_11b_scenario_hits"] == 0
    assert score["historical_p2_11b_scenario_total"] == 12
    assert score["detector_repo_commit"] == (
        "456b2a8238837026c8249ae1020b16249715bc04"
    )
    assert score["rules_tree_sha256"] == (
        "b42725734f70cfc87ccd0122e6ab90da2169d7599b2abaaf22c27050efa0c4d2"
    )
    assert score["rule_file_count"] == 4
    assert score["rules"] == 61
    assert score["events"] == 902
    assert score["findings"] == 84
    assert score["flagged_events"] == 80
    assert score["scenario_hits"] == 2
    assert score["scenario_misses"] == 10
    assert score["scenario_total"] == 12
    assert score["changed_scenarios"] == ["T1136.001-4", "T1136.001-5"]
    assert score["workflow_run_id"] == 34434077438
    assert score["artifact_id"] == 10135538509
    assert score["artifact_sha256"] == (
        "9f4a28b595c98afbd4f973ade5742654d96eed620f3133617234e5d9db533c11"
    )
    assert score["aggregate_result_sha256"] == (
        "f059c386a85d028938adafe2bc9519a732261d324711654b590e65544dbb1920"
    )


def test_p2_11d_permanent_measurement_matches_external_calibration() -> None:
    measurement = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    aggregate = json.loads(AGGREGATE.read_text(encoding="utf-8"))

    assert measurement["schema"] == (
        "breachscope.p2_11d_external_calibration_measurement.v1"
    )
    assert measurement["measurement_class"] == "external_calibration"
    assert measurement["measurement_repo_commit"] == (
        "456b2a8238837026c8249ae1020b16249715bc04"
    )
    assert measurement["from_rules_tree_sha256"] == (
        "371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f"
    )
    assert measurement["to_rules_tree_sha256"] == (
        "b42725734f70cfc87ccd0122e6ab90da2169d7599b2abaaf22c27050efa0c4d2"
    )

    assert aggregate["schema"] == "breachscope.p2_11d_external_calibration_result.v1"
    assert aggregate["evaluation_class"] == "external_calibration"
    assert aggregate["scenario_hits"] == 2
    assert aggregate["scenario_misses"] == 10
    assert aggregate["scenario_total"] == 12
    assert aggregate["events"] == 902
    assert aggregate["rules"] == 61
    assert aggregate["findings"] == 84
    assert aggregate["flagged_events"] == 80

    outcome_map = {
        row["scenario_id"]: row["status"]
        for row in aggregate["outcomes"]
    }
    assert outcome_map["T1136.001-4"] == "hit"
    assert outcome_map["T1136.001-5"] == "hit"
    assert sum(status == "hit" for status in outcome_map.values()) == 2


def test_p2_11d_claim_boundary_stays_narrow() -> None:
    boundary = _record()["claim_boundary"]
    assert boundary["p2_11b_historical_score_unchanged"] is True
    assert boundary["final_blind_holdout"] is False
    assert boundary["fresh_external_baseline"] is False
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["current_rulepack_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["event_level_precision_recall"] == "NOT_CLAIMED"
