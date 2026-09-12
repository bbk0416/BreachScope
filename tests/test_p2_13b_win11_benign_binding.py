from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "external_baseline" / "p2_13b_win11_benign_binding.json"
RECORD = ROOT / "external_baseline" / "p2_13b_win11_benign_binding.yaml"
SELECTION = ROOT / "external_baseline" / "p2_13a_win11_benign_selection.yaml"

EXPECTED_RAW_SHA256 = "b37bb8c1ca9b37eb5165f8d318da5b348fdb5b538ce20c4e39a5e29c263d34c3"
EXPECTED_ARCHIVE_SHA256 = "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
EXPECTED_DETECTOR = "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
EXPECTED_RULE_TREE = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"


def test_raw_binding_bytes_are_locked() -> None:
    assert hashlib.sha256(RAW.read_bytes()).hexdigest() == EXPECTED_RAW_SHA256


def test_binding_inventory_and_no_detector_execution() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["archive_sha256"] == EXPECTED_ARCHIVE_SHA256
    assert raw["evtx_files"] == 381
    assert raw["evtx_chunks"] == 39927
    assert raw["total_records"] == 1741090
    assert raw["sysmon_records"] == 1425626
    assert raw["sysmon_event1"] == 2302
    assert raw["parse_errors"] == 51
    assert raw["detector_imported"] is False
    assert raw["detector_executed"] is False
    assert raw["results_consulted"] is False
    assert raw["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"


def test_binding_record_links_canonical_execution_and_preserves_claims() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    assert record["selection_record"] == "external_baseline/p2_13a_win11_benign_selection.yaml"
    assert record["source"]["archive_sha256"] == EXPECTED_ARCHIVE_SHA256
    execution = record["binding_execution"]
    assert execution["method"] == "chunk_sharded_full_evtx_xml_inventory"
    assert execution["shard_count"] == 16
    assert execution["source_shard_run_id"] == 34680672963
    assert execution["source_shard_head_sha"] == "6efb3d17262effa7dffefad9ffcac8707f6bf4c7"
    assert execution["source_shard_jobs_successful"] == 16
    assert execution["source_aggregate_job_status"] == "failed"
    assert execution["source_aggregate_failure_class"] == "aggregate_runner_missing_python_evtx"
    assert execution["recovery_run_id"] == 34681354126
    assert execution["recovery_head_sha"] == "5efabdd7685cc35f58dfe0e03c1c57d2fb4b6082"
    assert execution["recovery_status"] == "success"
    assert execution["canonical_artifact_id"] == 10293984052
    assert execution["canonical_artifact_zip_sha256"] == "037a975fe7e3422154c4c3a863ed99272ab36a5af247294970969762060bfdda"
    assert execution["canonical_inner_result_sha256"] == EXPECTED_RAW_SHA256
    assert record["stored_result"]["sha256"] == EXPECTED_RAW_SHA256
    assert record["inventory"]["parse_errors"] == 51
    assert record["protocol"] == {
        "detector_imported": False,
        "detector_executed": False,
        "detector_results_consulted": False,
        "full_rulepack_scoring_performed": False,
        "detector_tuning_performed": False,
    }
    frozen = record["frozen_detector_reserved_for_next_stage"]
    assert frozen["repo_commit"] == EXPECTED_DETECTOR
    assert frozen["rules_tree_sha256"] == EXPECTED_RULE_TREE
    assert frozen["rule_count"] == 66
    assert record["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"


def test_pre_download_selection_remains_intact() -> None:
    selection = yaml.safe_load(SELECTION.read_text(encoding="utf-8"))
    assert selection["selected_before_archive_download"] is True
    assert selection["selected_before_detector_execution"] is True
    assert selection["freshness_boundary"]["selected_asset_previously_scored_by_breachscope"] is False
    assert selection["freshness_boundary"]["selected_asset_bytes_downloaded_before_selection"] is False
    assert selection["freshness_boundary"]["selected_asset_detector_results_consulted_before_selection"] is False
    assert selection["frozen_detector"]["repo_commit"] == EXPECTED_DETECTOR
    assert selection["frozen_detector"]["rules_tree_sha256"] == EXPECTED_RULE_TREE
    assert selection["frozen_detector"]["rule_count"] == 66
    assert selection["planned_measurement"]["tune_detector_after_result"] is False
