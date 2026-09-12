from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CLOSURE = ROOT / "external_baseline" / "p2_12_external_evidence_closure.yaml"


def _load():
    return yaml.safe_load(CLOSURE.read_text(encoding="utf-8"))


def test_p2_12_closure_preserves_frozen_detector() -> None:
    d = _load()
    assert d["schema"] == "breachscope.p2_12_external_evidence_closure.v1"
    assert d["frozen_detector"] == {
        "repo_commit": "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb",
        "rules_tree_sha256": "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92",
        "rule_count": 66,
        "rule_file_count": 4,
    }


def test_p2_12_closure_keeps_day1_and_day2_evidence_classes_separate() -> None:
    d = _load()
    day1 = d["day1"]
    day2 = d["day2"]
    assert day1["evidence_class"] == "fresh_external_holdout"
    assert day1["events"] == 196081
    assert day1["parse_errors"] == 0
    assert day1["exact_legacy_id_overlap_count"] == 1
    assert day1["exact_legacy_id_overlap"] == ["T1140"]
    assert day1["post_result_semantic_source_match_count"] == 5
    assert day2["evidence_class"] == "confirmatory_same_campaign_holdout"
    assert day2["events"] == 587286
    assert day2["parse_errors"] == 0
    assert day2["exact_legacy_id_overlap_count"] == 1
    assert day2["exact_legacy_id_overlap"] == ["T1047"]
    assert day2["post_result_semantic_source_match_count"] == 6


def test_p2_12_closure_forbids_combined_performance_metric() -> None:
    d = _load()
    agg = d["aggregation_boundary"]
    assert agg["day1_and_day2_combined_recall"] == "NOT_COMPUTED"
    assert agg["day1_and_day2_combined_detection_rate"] == "NOT_COMPUTED"
    assert agg["combined_exact_overlap_fraction"] == "NOT_COMPUTED"
    claims = d["claim_boundary"]
    assert claims["production_detection_rate"] == "NOT_CLAIMED"
    assert claims["production_precision"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["combined_day1_day2_performance_metric"] == "NOT_CLAIMED"


def test_p2_12_closure_records_phase_completion_without_overclaiming() -> None:
    d = _load()
    assert d["completed_phases"] == [
        "P2-12A", "P2-12B", "P2-12C", "P2-12D",
        "P2-12E", "P2-12F", "P2-12G", "P2-12H",
    ]
    assert d["closure_status"] == "CLOSED"
    assert d["claim_boundary"]["independent_fresh_external_holdout_for_day1"] is True
    assert d["claim_boundary"]["independent_fresh_external_holdout_for_day2"] is False
    assert d["claim_boundary"]["final_blind_holdout"] is False
    assert d["claim_boundary"]["event_level_ground_truth"] == "NOT_AVAILABLE"
