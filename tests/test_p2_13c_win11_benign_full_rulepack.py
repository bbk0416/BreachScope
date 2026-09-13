from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "external_baseline" / "p2_13c_win11_benign_full_rulepack.yaml"

EXPECTED_ARCHIVE_SHA256 = "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
EXPECTED_DETECTOR = "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
EXPECTED_RULE_TREE = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
EXPECTED_ZIP_SHA256 = "bb05ae809f518abef31965e362ab5d69c5280bc94364dc3a482a0ce4bc70dae3"
EXPECTED_INNER_SHA256 = "bf16d6b0b1b299d346efa136d2b1918a644ed9c56436c9684cd59b4c84bba940"


def load_record() -> dict:
    return yaml.safe_load(RECORD.read_text(encoding="utf-8"))


def test_execution_and_frozen_detector_are_locked() -> None:
    record = load_record()
    assert record["selection_record"] == "external_baseline/p2_13a_win11_benign_selection.yaml"
    assert record["binding_record"] == "external_baseline/p2_13b_win11_benign_binding.yaml"
    assert record["source"]["archive_sha256"] == EXPECTED_ARCHIVE_SHA256
    execution = record["execution"]
    assert execution["run_id"] == 34681845194
    assert execution["control_head_sha"] == "f7b3c1741568d44bd1b8520aae621574db3b0ea3"
    assert execution["canonical_artifact_id"] == 10294577794
    assert execution["canonical_artifact_zip_sha256"] == EXPECTED_ZIP_SHA256
    assert execution["canonical_inner_result_sha256"] == EXPECTED_INNER_SHA256
    assert execution["shard_count"] == 16
    assert execution["shard_jobs_successful"] == 16
    assert execution["aggregate_status"] == "success"
    frozen = record["frozen_detector"]
    assert frozen["repo_commit"] == EXPECTED_DETECTOR
    assert frozen["rules_tree_sha256"] == EXPECTED_RULE_TREE
    assert frozen["rule_count"] == 66
    assert frozen["rule_file_count"] == 4


def test_operational_alert_volume_is_measured_without_fpr_claim() -> None:
    record = load_record()
    inventory = record["inventory"]
    assert inventory == {
        "evtx_files": 381,
        "total_records": 1741090,
        "parse_errors": 51,
        "parsed_records": 1741039,
    }
    measurement = record["measurement"]
    assert measurement["findings"] == 54
    assert measurement["flagged_events"] == 54
    assert measurement["detected_rule_count"] == 7
    assert measurement["flagged_event_fraction_of_parsed_records"] == 3.101596230756462e-05
    assert measurement["tuning_performed_after_result"] is False
    assert sum(measurement["findings_by_rule"].values()) == 54
    boundary = record["claim_boundary"]
    assert boundary["operational_alert_volume"] == "MEASURED"
    assert boundary["fresh_public_benign_by_source_intent_corpus"] is True
    assert boundary["event_level_benign_ground_truth"] == "NOT_AVAILABLE"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["production_precision"] == "NOT_CLAIMED"
    assert boundary["production_recall"] == "NOT_CLAIMED"
    assert boundary["representative_production_population"] == "NOT_CLAIMED"
