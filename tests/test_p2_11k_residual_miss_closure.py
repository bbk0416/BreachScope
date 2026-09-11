from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "external_baseline" / "p2_11k_residual_miss_closure.json"
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"
P2_11J = ROOT / "external_baseline" / "results" / "p2_11j_357b7ea8" / "measurement.yaml"


def test_p2_11k_residual_review_closes_without_rule_change() -> None:
    review = json.loads(REVIEW.read_text(encoding="utf-8"))

    assert review["schema"] == "breachscope.p2_11k_residual_miss_closure.v1"
    assert review["review_class"] == "evidence_only_no_rule_change"
    assert review["current_rules_tree_sha256"] == (
        "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    )
    assert review["current_rule_count"] == 66
    assert review["current_external_calibration"]["scenario_hits"] == 9
    assert review["current_external_calibration"]["scenario_misses"] == 3
    assert review["current_external_calibration"]["scenario_total"] == 12
    assert review["current_external_calibration"]["remaining_miss_scenarios"] == [
        "T1003-1",
        "T1021.001-1",
        "T1021.001-2",
    ]
    assert [row["disposition"] for row in review["residual_reviews"]] == [
        "NO_GO_HOLD",
        "NO_GO_HOLD",
        "NO_GO_HOLD",
    ]
    assert review["decision"]["new_rule_added"] is False
    assert review["decision"]["rule_tree_changed"] is False
    assert review["decision"]["calibration_rerun_required"] is False
    assert review["decision"]["external_calibration_ceiling_for_current_fixed_suite"] == "9/12"
    assert review["decision"]["status"] == "CLOSE_RESIDUALS_NO_GO"


def test_p2_11k_does_not_rewrite_current_detection_chain() -> None:
    current = yaml.safe_load(CURRENT.read_text(encoding="utf-8"))
    measurement = yaml.safe_load(P2_11J.read_text(encoding="utf-8"))

    assert current["current_evidence_id"] == "p2-11j-current-detection-evidence"
    calibration_ids = [row["calibration_id"] for row in current["calibrations"]]
    assert calibration_ids[-1] == "p2-11j-t1003-networkprovider-credential-capture"
    assert not any(value.startswith("p2-11k") for value in calibration_ids)

    external = measurement["external_calibration"]
    assert external["after_scenario_hits"] == 9
    assert external["scenario_misses"] == 3
    assert external["scenario_total"] == 12
    assert external["remaining_miss_scenarios"] == [
        "T1003-1",
        "T1021.001-1",
        "T1021.001-2",
    ]
    assert measurement["to_rules_tree_sha256"] == (
        "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    )


def test_p2_11k_claim_boundaries_remain_explicit() -> None:
    review = json.loads(REVIEW.read_text(encoding="utf-8"))
    claims = review["claim_boundary"]

    assert claims["historical_p2_11b_baseline"] == "0/12_IMMUTABLE"
    assert claims["current_external_calibration"] == "9/12_EXTERNAL_CALIBRATION_ONLY"
    assert claims["production_detection_rate"] == "NOT_CLAIMED"
    assert claims["production_precision"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["fresh_blind_holdout"] is False
    assert claims["fresh_external_baseline"] is False
