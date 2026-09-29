from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "external_baseline"
    / "p2_36b_current_rulepack_fresh_source_preregistration.yaml"
)
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_36b_retires_p2_36_and_freezes_same_product() -> None:
    row = _load()
    assert row["analysis_id"] == (
        "p2-36b-current-rulepack-fresh-source-revalidation-v1"
    )
    assert row["status"] == "PREREGISTERED_SOURCE_SELECTION_NOT_RUN"
    assert row["predecessor"]["same_analysis_id_retry_forbidden"] is True
    assert row["predecessor"]["predecessor_attack_fixtures_reused"] is False
    assert row["predecessor"]["predecessor_benign_archive_reused"] is False
    assert row["frozen_product"] == {
        "repo_commit": "a469378c0b26bb25ab005ecf2edd681a0b126713",
        "rules_tree_sha256": (
            "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
        ),
        "rule_count": 73,
        "rule_file_count": 5,
        "product_changed_from_p2_36": False,
    }


def test_p2_36b_attack_source_is_new_and_preselected() -> None:
    attack = _load()["attack_revalidation"]
    source = attack["source"]
    assert source["repository"] == "0xx0d4y/Malware_Research_EVTX"
    assert source["pinned_commit"] == (
        "24d78c6401672c8a1d690e660e351c51f528414f"
    )
    assert source["readme_git_blob_sha1"] == (
        "06ed0710874b506ae2ccc178717ad30ca380edfe"
    )
    assert source["source_family_previously_used_by_breachscope"] is False

    fresh = attack["freshness_evidence"]
    assert fresh["source_repository_reference_count_in_pre_p2_36b_repo"] == 0
    assert fresh["selected_source_path_reference_count_in_pre_p2_36b_repo"] == 0
    assert fresh["selected_git_blob_id_reference_count_in_pre_p2_36b_repo"] == 0
    assert fresh["exact_byte_sha256_not_yet_bound"] is True

    policy = attack["selection_policy"]
    assert policy["selected_fixture_count"] == 1
    assert policy["all_selector_matches_selected"] is True
    assert policy["single_fixture_source_limitation"] is True
    assert policy["post_execution_fixture_replacement_allowed"] is False

    rows = attack["datasets"]
    assert rows == [
        {
            "dataset_id": "amadey_9c9aa5_campaign",
            "family_label": "Amadey 9c9aa5 Campaign",
            "source_path": "Amadey - 9c9aa5 Campaign/9c9aa5_campaign.evtx",
            "size_bytes": 3_215_360,
            "git_blob_sha1": "6a9ae012734b9fe86a5fcf5a804f69e13170ab8c",
        }
    ]


def test_p2_36b_benign_asset_is_new_exact_asset_candidate() -> None:
    benign = _load()["benign_revalidation"]
    assert benign["source"]["repository"] == "NextronSystems/evtx-baseline"
    assert benign["source"]["release_tag"] == "v0.8.5"
    assert benign["source"]["source_family_previously_used_by_breachscope"] is True

    fresh = benign["freshness_evidence"]
    assert fresh["selected_asset_name_reference_count_in_pre_p2_36b_repo"] == 0
    assert fresh["selected_asset_sha256_reference_count_in_pre_p2_36b_repo"] == 0
    assert fresh["archive_inventory_before_merge"] is False
    assert fresh["event_contents_parsed_for_selection"] is False

    assert benign["archive"] == {
        "asset_name": "win11-client.tgz",
        "size_bytes": 133_144_670,
        "sha256": (
            "6caab8391ac3cf7135e2fd5f545c7b116a2b445ec061f83d05873f8081ff0202"
        ),
        "digest_source": "GITHUB_RELEASE_V0_8_5_ASSET_METADATA",
    }
    assert (
        benign["member_selection_policy"]["zero_parsed_event_member_policy"]
        == "RECORD_EMPTY_AND_CONTINUE"
    )


def test_p2_36b_execution_gate_fixes_empty_evtx_failure_mode() -> None:
    gate = _load()["execution_gate"]
    assert gate["source_preregistration_must_be_merged_before_exact_byte_binding"] is True
    assert gate["separate_execution_contract_required"] is True
    assert gate["successor_runner_must_record_zero_event_evtx_as_empty"] is True
    assert (
        gate["successor_runner_must_not_fail_only_because_evtx_has_zero_parsed_events"]
        is True
    )
    assert gate["detector_must_not_run_before_execution_contract_merge"] is True


def test_p2_36b_current_evidence_still_has_no_completed_fresh_revalidation() -> None:
    current = yaml.safe_load(CURRENT.read_text(encoding="utf-8"))
    validation = current["current_rulepack_validation"]
    assert validation["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert validation["fresh_benign_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert validation["fresh_current_rulepack_performance_available"] is False


def test_p2_36b_claim_boundary_stays_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["attack_source_family_previously_used_by_breachscope"] is False
    assert claim["benign_source_family_previously_used_by_breachscope"] is True
    assert claim["attack_source_contains_single_selected_fixture"] is True
    assert claim["combined_independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_fraction_is_event_level_recall"] is False
    assert claim["benign_flagged_events_are_confirmed_false_positives"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36b_execution_not_started() -> None:
    row = _load()
    assert row["preregistration"]["attack_exact_bytes_downloaded_for_p2_36b_before_merge"] is False
    assert row["preregistration"]["benign_archive_downloaded_for_p2_36b_before_merge"] is False
    assert row["execution_state_at_preregistration"] == {
        "source_contract_merged": False,
        "execution_contract_merged": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }
