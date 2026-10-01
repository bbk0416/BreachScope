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
    assert source["corpus_archive"]["sha256"] == (
        "TO_BE_BOUND_AFTER_PREREGISTRATION_MERGE"
    )
    assert source["groundtruth_archive"]["sha256"] == (
        "TO_BE_BOUND_AFTER_PREREGISTRATION_MERGE"
    )


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
    assert labels["class_1_to_external_holdout_label"] == "malicious"
    assert labels["class_2_to_external_holdout_label"] == "ignore"
    assert labels["remaining_test_window_event_to_external_holdout_label"] == "benign"
    assert labels["class_2_excluded_from_confusion_matrix_denominators"] is True
    assert (
        labels[
            "class_1_and_class_2_must_be_exact_subsets_of_selected_winlogbeat_events"
        ]
        is True
    )
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
