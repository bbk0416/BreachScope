from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "external_baseline"
    / "p2_36_current_rulepack_fresh_source_preregistration.yaml"
)
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_36_freezes_current_73_rule_product() -> None:
    row = _load()
    assert row["analysis_id"] == (
        "p2-36-current-rulepack-fresh-source-revalidation-v1"
    )
    assert row["status"] == "PREREGISTERED_SOURCE_SELECTION_NOT_RUN"
    assert row["preregistration"]["base_main_commit"] == (
        "a469378c0b26bb25ab005ecf2edd681a0b126713"
    )
    assert row["frozen_product"] == {
        "repo_commit": "a469378c0b26bb25ab005ecf2edd681a0b126713",
        "rules_tree_sha256": (
            "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
        ),
        "rule_count": 73,
        "rule_file_count": 5,
    }


def test_p2_36_attack_source_is_new_and_all_evtx_are_preselected() -> None:
    attack = _load()["attack_revalidation"]
    source = attack["source"]
    assert source["repository"] == "G4rb3n/Malware-EVTX"
    assert source["pinned_commit"] == (
        "d8d250d3b55779e81552adf2a5f98be1b1cfeb2f"
    )
    assert source["readme_git_blob_sha1"] == (
        "14e9fb5d59957d55c72b244a18b0a88d8d4739ad"
    )
    assert source["source_family_previously_used_by_breachscope"] is False

    fresh = attack["freshness_evidence"]
    assert fresh["source_repository_reference_count_in_pre_p2_36_repo"] == 0
    assert fresh["selected_source_path_reference_count_in_pre_p2_36_repo"] == 0
    assert fresh["selected_git_blob_id_reference_count_in_pre_p2_36_repo"] == 0
    assert fresh["exact_byte_sha256_not_yet_bound"] is True
    assert fresh["attack_event_contents_parsed_for_selection"] is False

    policy = attack["selection_policy"]
    assert policy["all_selector_matches_selected"] is True
    assert policy["selected_fixture_count"] == 7
    assert policy["post_execution_fixture_replacement_allowed"] is False

    datasets = attack["datasets"]
    assert len(datasets) == 7
    assert len({x["source_path"] for x in datasets}) == 7
    assert all(x["source_path"].lower().endswith(".evtx") for x in datasets)
    assert all(len(x["git_blob_sha1"]) == 40 for x in datasets)
    assert sum(int(x["size_bytes"]) for x in datasets) == 1_536_000


def test_p2_36_benign_archive_is_unused_asset_candidate() -> None:
    benign = _load()["benign_revalidation"]
    assert benign["source"]["repository"] == "NextronSystems/evtx-baseline"
    assert benign["source"]["release_tag"] == "v0.8.5"
    assert benign["source"]["source_family_previously_used_by_breachscope"] is True

    fresh = benign["freshness_evidence"]
    assert fresh["selected_asset_name_reference_count_in_pre_p2_36_repo"] == 0
    assert fresh["selected_asset_sha256_reference_count_in_pre_p2_36_repo"] == 0
    assert fresh["archive_inventory_before_merge"] is False
    assert fresh["event_contents_parsed_for_selection"] is False

    assert benign["archive"] == {
        "asset_name": "win2022-0-20348-azure.tgz",
        "size_bytes": 143_223_928,
        "sha256": (
            "4b3337d857f8e03273f831ad25db75e02a5a8b26b5ec14bb63727459250a5a73"
        ),
        "digest_source": "GITHUB_RELEASE_V0_8_5_ASSET_METADATA",
    }
    assert benign["member_selection_policy"]["post_inventory_member_dropping_allowed"] is False
    assert benign["member_selection_policy"]["fallback_to_different_asset_allowed"] is False


def test_p2_36_current_evidence_now_points_to_p2_36c_completed_revalidation() -> None:
    current = yaml.safe_load(CURRENT.read_text(encoding="utf-8"))
    validation = current["current_rulepack_validation"]
    assert validation["current_revalidation_id"] == "p2-36c-current-rulepack-fresh-source-revalidation"
    assert validation["fresh_attack_revalidation_after_current_rule_change"] == "COMPLETED"
    assert validation["fresh_benign_revalidation_after_current_rule_change"] == "COMPLETED"
    assert validation["fresh_current_rulepack_performance_available"] is True


def test_p2_36_execution_gate_prevents_premature_scoring() -> None:
    row = _load()
    gate = row["execution_gate"]
    assert gate["source_preregistration_must_be_merged_before_runner_freeze"] is True
    assert gate["separate_execution_contract_required"] is True
    assert gate["execution_contract_must_freeze_runner_sha256"] is True
    assert gate["execution_contract_must_bind_attack_sha256_after_source_download"] is True
    assert gate["execution_contract_must_define_permanent_global_lock"] is True
    assert gate["detector_must_not_run_before_execution_contract_merge"] is True
    assert gate["source_or_fixture_selection_must_not_depend_on_detector_output"] is True
    assert row["execution_state_at_preregistration"] == {
        "source_contract_merged": False,
        "execution_contract_merged": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }


def test_p2_36_claim_boundary_remains_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["attack_source_family_previously_used_by_breachscope"] is False
    assert claim["benign_source_family_previously_used_by_breachscope"] is True
    assert claim["combined_independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_fraction_is_event_level_recall"] is False
    assert claim["benign_flagged_events_are_confirmed_false_positives"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
