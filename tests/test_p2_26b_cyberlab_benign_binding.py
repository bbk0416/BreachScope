from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_26b_cyberlab_benign_binding.yaml"
RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
SOURCE_COMMIT = "a5f2c0dbe64b7201fdc2c47eb23efc119115d652"
EXPECTED_SHA = "452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88"
ACTUAL_SHA = "f56a7c918e212b2c77a518ab57768c873fc6666c98f366c24b7c9b0e88ac916c"
BLOB = "540677984c675604d9318ee9accc3ce823ea60f5"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_26b_binding_history_is_preserved_and_aborted() -> None:
    row = _load()
    assert row["schema"] == "breachscope.p2_26b_cyberlab_benign_binding.v2"
    assert row["status"] == "ABORTED_SOURCE_IDENTITY_MISMATCH"
    assert row["analysis_class"] == "aborted_source_identity_mismatch_external_benign_source_binding"
    assert row["binding_base_commit"] == "2fefbb4e19c1473304bb3fbeba019ddbbb44b41e"
    detector = row["frozen_detector"]
    assert detector["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert detector["rules_tree_sha256"] == RULE_HASH
    assert detector["rule_count"] == 68


def test_p2_26b_preserves_pre_observation_identity_contract() -> None:
    source = _load()["source"]
    assert source["repository"] == "project-cyberlab/cyberlab"
    assert source["pinned_repository_commit"] == SOURCE_COMMIT
    selected = source["selected_file"]
    assert selected["git_blob_sha1"] == BLOB
    assert selected["size_bytes"] == 69632
    assert selected["upstream_declared_sha256"] == EXPECTED_SHA

    basis = _load()["selection_basis"]
    assert basis["selected_file_bytes_downloaded_before_binding"] is False
    assert basis["selected_file_opened_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False


def test_p2_26b_phase_b_detected_sha_identity_mismatch_before_parse() -> None:
    observed = _load()["post_binding_observation"]
    assert observed["binding_merge_commit"] == "50c99ab4dd0e02f7eb91ef98ba7b4046af6d3eda"
    assert observed["selected_file_downloaded_after_binding_merge"] is True
    assert observed["first_transfer_attempt"] == "FAILED_ZERO_BYTE_POWERSHELL_BINARY_REDIRECTION"
    assert observed["first_transfer_output_used_as_evidence"] is False
    assert observed["downloaded_size_bytes"] == 69632
    assert observed["downloaded_git_blob_sha1"] == BLOB
    assert observed["downloaded_sha256"] == ACTUAL_SHA
    assert observed["size_match"] is True
    assert observed["git_blob_sha1_match"] is True
    assert observed["upstream_declared_sha256_match"] is False
    assert observed["evtx_records_parsed"] is False
    assert observed["breachscope_detector_executed"] is False
    assert observed["source_file_deleted_after_identity_record"] is True


def test_p2_26b_crosscheck_explains_upstream_documentation_inconsistency() -> None:
    cross = _load()["upstream_identity_crosscheck"]
    assert len(cross["same_git_blob_paths"]) == 3
    assert cross["all_three_paths_git_blob_sha1"] == BLOB
    assert cross["all_three_paths_size_bytes"] == 69632
    assert cross["module_58_and_60_readme_declared_sha256"] == ACTUAL_SHA
    assert "internally inconsistent" in cross["interpretation"]


def test_p2_26b_abort_blocks_measurement_and_hash_rewrite() -> None:
    row = _load()
    abort = row["abort"]
    assert abort["expected_upstream_sha256"] == EXPECTED_SHA
    assert abort["actual_pinned_blob_sha256"] == ACTUAL_SHA
    assert abort["exact_size_match"] is True
    assert abort["exact_git_blob_sha1_match"] is True
    assert abort["sha256_match"] is False
    assert abort["eligible_for_fresh_benign_revalidation"] is False
    assert abort["measurement_prohibited_after_abort"] is True
    assert abort["evtx_records_parsed"] is False
    assert abort["detector_execution_after_binding"] is False
    assert abort["result_driven_expected_hash_rewrite_allowed"] is False
    assert row["protocol"]["measurement_prohibited_after_abort"] is True

    claim = row["claim_boundary"]
    assert claim["fresh_benign_revalidation"] == "ABORTED_SOURCE_IDENTITY_MISMATCH"
    assert claim["source_intent_benign_flagged_event_fraction"] == "NOT_MEASURED_SOURCE_IDENTITY_MISMATCH"
    assert claim["general_fresh_full_benign_fpr"] == "NOT_CLAIMED"
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
