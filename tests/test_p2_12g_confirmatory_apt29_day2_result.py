from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_12g_13eb8f6a"
RESULT = RESULT_DIR / "apt29-day2-result.json"
FREEZE = RESULT_DIR / "rules-freeze.json"
MEASUREMENT = RESULT_DIR / "measurement.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_12g_raw_artifact_bytes_are_locked() -> None:
    assert _sha256(RESULT) == "ebf45b29b1b16bf85ebc297cd9a79b19b6b1e0b507788c3b5ef8e807150e411d"
    assert _sha256(FREEZE) == "49ce5c828fd51a6638da085a62ced8b1d458e5045baa00826449f8ec61ea5f86"


def test_p2_12g_confirmatory_result_is_exact() -> None:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    assert result["schema"] == "breachscope.p2_12g_confirmatory_holdout_result.v1"
    assert result["evaluation_class"] == "confirmatory_same_campaign_holdout"
    assert result["detector_repo_commit"] == "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
    assert result["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert result["rules"] == 66
    assert result["events"] == 587286
    assert result["parse_errors"] == 0
    assert result["findings"] == 27
    assert result["flagged_events"] == 22
    assert result["detected_rule_count"] == 10
    assert result["detected_technique_count"] == 8
    assert result["source_legacy_technique_total"] == 41
    assert result["exact_legacy_id_overlap_count"] == 1
    assert result["exact_legacy_id_overlap"] == ["T1047"]
    assert result["claim_boundary"]["fresh_external_corpus"] is False
    assert result["claim_boundary"]["independent_external_source_from_day1"] is False
    assert result["claim_boundary"]["same_campaign_as_day1"] is True


def test_p2_12g_measurement_preserves_protocol_and_claim_boundaries() -> None:
    m = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    assert m["measurement_class"] == "confirmatory_same_campaign_holdout"
    assert m["protocol"]["day2_selected_before_archive_download"] is True
    assert m["protocol"]["archive_bytes_bound_before_detection"] is True
    assert m["protocol"]["day2_labels_bound_before_detection"] is True
    assert m["protocol"]["detector_results_unseen_before_first_day2_scoring"] is True
    assert m["protocol"]["first_day2_scoring_run_id"] == 34672342976
    assert m["protocol"]["day1_result_already_observed"] is True
    assert m["protocol"]["tuning_after_day1_before_day2"] is False
    assert m["protocol"]["same_campaign_as_day1"] is True
    assert m["result"]["stored_result_sha256"] == _sha256(RESULT)
    assert m["result"]["rules_freeze_sha256"] == _sha256(FREEZE)
    assert m["execution_evidence"]["artifact_id"] == 10291276516
    assert m["execution_evidence"]["artifact_digest_sha256"] == "5405d09f1ab56612ba48c2bc3776df6f1bb64827d3c1498cb87cfdf94ea7b198"
    assert m["source_label_comparison"]["exact_legacy_id_overlap_count"] == 1
    assert m["source_label_comparison"]["exact_legacy_id_overlap"] == ["T1047"]
    assert m["claim_boundary"]["confirmatory_same_campaign_holdout"] is True
    assert m["claim_boundary"]["independent_fresh_external_holdout"] is False
    assert m["claim_boundary"]["fresh_external_corpus"] is False
    assert m["claim_boundary"]["final_blind_holdout"] is False
    assert m["claim_boundary"]["event_level_labels"] == "NOT_AVAILABLE"
    assert m["claim_boundary"]["production_detection_rate"] == "NOT_CLAIMED"
    assert m["claim_boundary"]["production_precision"] == "NOT_CLAIMED"
    assert m["claim_boundary"]["production_recall"] == "NOT_CLAIMED"
    assert m["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert m["claim_boundary"]["exact_legacy_id_overlap_is_recall"] is False
