from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "external_baseline"
    / "p2_37_dedale_event_level_holdout_preregistration.yaml"
)


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_37_freezes_current_73_rule_product_before_source_download() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-37-dedale-event-level-holdout-v1"
    assert row["status"] == "PREREGISTERED_SOURCE_SELECTION_NOT_DOWNLOADED_NOT_RUN"
    assert row["preregistration"]["base_main_commit"] == (
        "0fcad967c4d1a04b58800c5d0e761a91c47b8773"
    )
    assert row["frozen_product"] == {
        "repo_commit": "0fcad967c4d1a04b58800c5d0e761a91c47b8773",
        "reference_detector_commit": "bad0c88037d489f5b375c120002be74ac6082ffa",
        "rules_tree_sha256": (
            "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
        ),
        "rule_count": 73,
        "rule_file_count": 5,
        "rule_bytes_unchanged_from_reference_detector": True,
    }


def test_p2_37_selects_previously_unused_dedale_windows_source() -> None:
    source = _load()["source"]
    assert source["dataset_name"] == "DEDALE"
    assert source["dataset_version"] == "2.0"
    assert source["persistent_id"] == "doi:10.57745/Y5JLDG"
    assert source["source_previously_used_by_breachscope"] is False
    assert source["repository_usage_before_p2_37"] == 0
    assert source["host_log_type"] == "WINLOGBEAT_WINDOWS_EVENTS"
    assert source["corpus_archive"]["provider_filename"] == (
        "system_logs_winlogbeat.zip"
    )
    assert source["groundtruth_archive"]["provider_filename"] == (
        "system_logs_labels.zip"
    )
    assert source["corpus_archive"]["sha256"] == "TO_BE_BOUND_AFTER_FULL_DOWNLOAD"
    assert source["groundtruth_archive"]["sha256"] == "TO_BE_BOUND_AFTER_FULL_DOWNLOAD"
    assert source["corpus_archive"]["file_persistent_id"] == "doi:10.57745/ATR0QO"
    assert source["corpus_archive"]["size_bytes"] == 27_123_250_952
    assert source["corpus_archive"]["provider_md5"] == (
        "7af54ba2977f7535d4c07beb6b1ec657"
    )
    assert source["corpus_archive"]["outer_zip_file_count"] == 673
    assert source["corpus_archive"]["member_format"] == "JSONL_BZ2"
    assert source["corpus_archive"]["extraction_required_before_adapter_run"] is False
    assert source["groundtruth_archive"]["file_persistent_id"] == "doi:10.57745/GFI7BE"
    assert source["groundtruth_archive"]["size_bytes"] == 2_669_407
    assert source["groundtruth_archive"]["provider_md5"] == (
        "455d0a7042531eff74285006f97822e4"
    )
    assert source["groundtruth_archive"]["separate_class_2_member_exists"] is False


def test_p2_37_uses_provider_recommended_test_window_without_tuning() -> None:
    row = _load()
    usage = row["source"]["provider_documented_usage"]
    assert usage["first_two_weeks"] == "BENIGN_ONLY"
    assert usage["recommended_training_validation_window"] == "FIRST_TWO_WEEKS"
    assert usage["recommended_test_window"] == "LAST_TWO_WEEKS"

    selection = row["selection_policy"]
    assert selection["scoring_window"] == "LAST_TWO_WEEKS_ONLY"
    assert selection["first_two_weeks_used_for_rule_tuning"] is False
    assert selection["first_two_weeks_scored_in_p2_37"] is False
    assert selection["post_score_member_or_event_dropping_allowed"] is False
    assert selection["fallback_to_first_two_weeks_allowed"] is False
    assert selection["fallback_to_different_dataset_allowed"] is False
    assert selection["if_test_window_cannot_be_reproduced"] == (
        "ABORT_BEFORE_SCORING"
    )


def test_p2_37_label_mapping_excludes_attack_related_context() -> None:
    labels = _load()["label_mapping_contract"]
    assert labels["provider_class_1_to_external_holdout_label"] == "malicious"
    assert labels["provider_class_2_derivation"] == (
        "CLASS_1_AND_2_EXACT_SET_MINUS_CLASS_1_EXACT_SET"
    )
    assert labels["derived_class_2_to_external_holdout_label"] == "ignore"
    assert labels["remaining_test_window_event_to_external_holdout_label"] == "benign"
    assert labels["derived_class_2_excluded_from_confusion_matrix_denominators"] is True
    assert labels["class_1_must_be_exact_subset_of_class_1_and_2"] is True
    assert (
        labels[
            "class_1_and_class_1_and_2_must_be_exact_subsets_of_selected_winlogbeat_events"
        ]
        is True
    )
    assert labels["auditbeat_internal_server_labels_must_not_enter_winlogbeat_scoring"] is True
    assert labels["exact_reconciliation_required_before_scoring"] is True
    assert labels["fuzzy_timestamp_or_process_name_matching_allowed"] is False
    assert labels["unmatched_groundtruth_event_policy"] == "ABORT_BEFORE_SCORING"
    assert labels["ambiguous_or_duplicate_groundtruth_match_policy"] == (
        "ABORT_BEFORE_SCORING"
    )
    assert (
        labels[
            "remaining_event_may_be_called_benign_only_after_subset_reconciliation_passes"
        ]
        is True
    )


def test_p2_37_blocks_detector_until_hashes_labels_and_contract_are_frozen() -> None:
    row = _load()
    gate = row["execution_gate"]
    assert gate["source_preregistration_must_be_merged_before_download"] is True
    assert gate["bind_exact_archive_hashes_before_indexing"] is True
    assert gate["provider_md5_must_match_before_processing"] is True
    assert gate["full_download_sha256_must_be_recorded_before_processing"] is True
    assert gate["outer_zip_must_be_streamed_without_bulk_extraction"] is True
    assert gate["freeze_current_repo_and_rule_tree_before_scoring"] is True
    assert gate["index_without_detection_before_label_generation"] is True
    assert gate["generated_label_file_must_be_hash_bound_before_scoring"] is True
    assert gate["label_generation_must_follow_only_the_preregistered_mapping"] is True
    assert gate["detector_must_not_run_before_execution_contract_merge"] is True
    assert gate["source_split_or_labels_must_not_depend_on_detector_output"] is True
    assert gate["single_canonical_scoring_run_required"] is True

    assert row["execution_state_at_preregistration"] == {
        "source_contract_merged": False,
        "corpus_downloaded": False,
        "groundtruth_downloaded": False,
        "exact_archive_hashes_bound": False,
        "event_index_created": False,
        "label_file_created": False,
        "execution_contract_merged": False,
        "detector_run": False,
        "result_observed": False,
    }


def test_p2_37_claim_boundary_does_not_turn_dataset_metrics_into_production_claims() -> None:
    claim = _load()["claim_boundary"]
    assert claim["evaluation_class"] == "external_baseline"
    assert claim["final_blind_holdout"] is False
    assert claim["event_level_labels_available_from_source"] is True
    assert claim["ground_truth_quality_independently_proven_by_breachscope"] is False
    assert claim["representative_production_population"] is False
    assert claim["successful_metrics_may_be_named_dedale_holdout_metrics"] is True
    assert claim["successful_metrics_may_be_named_production_metrics"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_precision"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_37_locks_source_derived_window_and_adapter_blob() -> None:
    row = _load()
    lock = row["post_preregistration_tool_lock"]
    assert lock["source_preregistration_merge_commit"] == (
        "4a6a5605e524ea3b742a7194a720effce7d48fb6"
    )
    assert lock["adapter_merge_commit_before_window_lock"] == (
        "47b0b6701209c89c8df366c2b9edc49a771fd1b7"
    )
    assert lock["adapter_path"] == "scripts/p2_37_prepare_dedale_holdout.py"
    assert lock["adapter_git_blob_sha1"] == (
        "31bf09ada2f5f511f0eea8ff492732178d848233"
    )
    assert lock["adapter_may_not_change_after_window_lock_merge"] is True
    assert lock["detector_code_changed_by_adapter_work"] is False
    assert lock["rule_tree_changed_by_adapter_work"] is False

    window = row["selection_policy"]["test_window_derivation"]
    assert window == {
        "method": "LAST_14_OF_EXACTLY_28_CONSECUTIVE_UTC_DATES",
        "required_distinct_utc_dates": 28,
        "require_consecutive_utc_dates": True,
        "derive_from_full_winlogbeat_before_normalization": True,
        "labels_may_be_read_during_window_derivation": False,
        "detector_may_run_during_window_derivation": False,
        "expected_start_and_end_must_be_recorded_in_execution_contract": True,
        "if_date_contract_fails": "ABORT_BEFORE_NORMALIZATION",
    }


def test_p2_37_requires_window_inspection_before_normalization() -> None:
    row = _load()
    gate = row["execution_gate"]
    assert gate["inspect_window_before_normalization"] is True
    assert gate["window_inspection_must_not_read_labels_or_run_detection"] is True
    assert gate["execution_contract_must_bind_derived_window_start_and_end"] is True
    assert row["post_window_lock_state"] == {
        "source_contract_merged": True,
        "window_lock_tool_merged": False,
        "remote_archive_metadata_inspected_by_range_only": True,
        "event_member_payload_read_during_remote_inspection": False,
        "corpus_downloaded": False,
        "groundtruth_downloaded": False,
        "exact_archive_hashes_bound": False,
        "window_inspected": False,
        "normalized_corpus_created": False,
        "event_index_created": False,
        "label_file_created": False,
        "execution_contract_merged": False,
        "detector_run": False,
        "result_observed": False,
    }
