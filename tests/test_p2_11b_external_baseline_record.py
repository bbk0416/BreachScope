from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "external_baseline" / "p2_11b_atomic_evtx_selection.yaml"
BINDING = ROOT / "external_baseline" / "p2_11b_atomic_evtx_byte_binding.json"
PLAN = ROOT / "external_baseline" / "p2_11b_atomic_evtx_score_plan.yaml"
RESULT = ROOT / "external_baseline" / "results" / "p2_11b_atomic_evtx_30f67ebb" / "aggregate-result.json"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_11b_atomic_evtx_30f67ebb" / "measurement.yaml"

EXPECTED_SCENARIOS = [
    "T1003-1",
    "T1003-2",
    "T1006-1",
    "T1027-2",
    "T1007-1",
    "T1007-2",
    "T1021.001-1",
    "T1021.001-2",
    "T1047-1",
    "T1047-2",
    "T1136.001-4",
    "T1136.001-5",
]


def _yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_p2_11b_selection_was_frozen_before_detection() -> None:
    selection = _yaml(SELECTION)
    assert selection["evaluation_class"] == "external_baseline"
    assert selection["selection_frozen_commit"] == "7541214400507afddca40a22f2adb22504fc3946"
    assert selection["selection_policy"]["detector_results_consulted_before_selection"] is False
    assert selection["selection_policy"]["selected_evtx_bytes_downloaded_before_selection"] is False
    assert [row["scenario_id"] for row in selection["scenarios"]] == EXPECTED_SCENARIOS
    assert selection["protocol_state"]["score_executed"] is True
    assert selection["protocol_state"]["future_tuning_on_these_scenarios_is_calibration"] is True
    assert selection["claim_boundary"]["final_blind_holdout"] is False


def test_p2_11b_byte_binding_precedes_detection_and_covers_all_selected_evtx() -> None:
    binding = json.loads(BINDING.read_text(encoding="utf-8"))
    assert binding["selection_commit"] == "7541214400507afddca40a22f2adb22504fc3946"
    assert binding["source_commit"] == "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
    assert binding["scenario_count"] == 12
    assert binding["evtx_file_count"] == 60
    assert binding["detection_executed"] is False
    assert [row["scenario_id"] for row in binding["scenarios"]] == EXPECTED_SCENARIOS
    assert sum(len(row["evtx_files"]) for row in binding["scenarios"]) == 60
    for row in binding["scenarios"]:
        assert len(row["evtx_files"]) == 5
        for item in row["evtx_files"]:
            assert item["bytes"] > 4096
            assert len(item["sha256"]) == 64


def test_p2_11b_score_plan_was_precommitted_without_threshold() -> None:
    plan = _yaml(PLAN)
    assert plan["frozen_detector"]["repo_commit"] == "674615ef3c92d5b4bbc4dec71f566d49de0454f4"
    assert plan["frozen_detector"]["rules_tree_sha256"] == (
        "371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f"
    )
    assert plan["scoring_protocol"]["score_order"] == EXPECTED_SCENARIOS
    assert plan["scoring_protocol"]["acceptance_threshold"] == "NONE_PREDECLARED"
    assert plan["protocol_attestations"]["detection_executed_before_this_plan"] is False
    assert plan["claim_boundary"]["final_blind_holdout"] is False


def test_p2_11b_record_preserves_zero_of_twelve_result_and_claim_boundaries() -> None:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    assert result["evaluation_class"] == "external_baseline"
    assert result["detector_repo_commit"] == "674615ef3c92d5b4bbc4dec71f566d49de0454f4"
    assert result["rules_tree_sha256"] == (
        "371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f"
    )
    assert result["rules"] == 60
    assert result["scenario_total"] == 12
    assert result["scenario_hits"] == 0
    assert result["scenario_misses"] == 12
    assert result["scenario_hit_rate"] == 0.0
    assert [row["scenario_id"] for row in result["outcomes"]] == EXPECTED_SCENARIOS
    assert all(row["status"] == "miss" for row in result["outcomes"])
    assert result["event_level"]["precision"] == "NOT_CLAIMED"
    assert result["event_level"]["recall"] == "NOT_CLAIMED"
    assert result["event_level"]["false_positive_rate"] == "NOT_CLAIMED"
    assert result["claim_boundary"]["final_blind_holdout"] is False
    assert result["claim_boundary"]["production_detection_rate"] == "NOT_CLAIMED"


def test_p2_11b_measurement_binds_exact_aggregate_result() -> None:
    measurement = _yaml(MEASUREMENT)
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    digest = hashlib.sha256(RESULT.read_bytes()).hexdigest()
    assert measurement["score_execution"]["aggregate_result_sha256"] == digest
    assert digest == "89a309b8b59c5602afb4e3de1136fe53d9284463a8e409625f6a633629071a11"
    assert measurement["score_execution"]["github_actions_run_id"] == 34389538790
    assert measurement["score_execution"]["artifact_id"] == 10119080561
    assert measurement["result"]["scenario_hits"] == result["scenario_hits"] == 0
    assert measurement["result"]["scenario_misses"] == result["scenario_misses"] == 12
    assert measurement["event_level_ground_truth"]["precision"] == "NOT_CLAIMED"
    assert measurement["claim_boundary"]["final_blind_holdout"] is False
