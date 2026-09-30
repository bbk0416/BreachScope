from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "external_baseline"
    / "p2_36c_current_rulepack_fresh_source_preregistration.yaml"
)
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_36c_retires_p2_36b_and_keeps_product_frozen() -> None:
    row = _load()
    assert row["analysis_id"] == (
        "p2-36c-current-rulepack-fresh-source-revalidation-v1"
    )
    assert row["status"] == "PREREGISTERED_SOURCE_SELECTION_NOT_RUN"
    assert row["predecessor"]["failed_analysis_id"] == (
        "p2-36b-current-rulepack-fresh-source-revalidation-v1"
    )
    assert row["predecessor"]["same_analysis_id_retry_forbidden"] is True
    assert row["predecessor"]["predecessor_attack_fixture_reused"] is False
    assert row["predecessor"]["predecessor_benign_archive_reused"] is False
    assert row["frozen_product"] == {
        "repo_commit": "a469378c0b26bb25ab005ecf2edd681a0b126713",
        "rules_tree_sha256": (
            "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
        ),
        "rule_count": 73,
        "rule_file_count": 5,
        "product_changed_from_p2_36b": False,
    }


def test_p2_36c_attack_repository_and_all_direct_evtx_are_preselected() -> None:
    attack = _load()["attack_revalidation"]
    source = attack["source"]
    assert source["repository"] == (
        "ChristosSmiliotopoulos/Python_Evtx_Analyzer"
    )
    assert source["pinned_commit"] == (
        "74fc950130d63141e50ad4975fd9045dbcfb7825"
    )
    assert source["readme_git_blob_sha1"] == (
        "20f520066fd5fbd236e01b3ee7eec66451e1e53d"
    )
    assert source["source_repository_previously_used_by_breachscope"] is False
    assert source["author_overlap_with_prior_lmd_candidate"] is True

    fresh = attack["freshness_evidence"]
    assert fresh["source_repository_reference_count_in_pre_p2_36c_repo"] == 0
    assert fresh["selected_source_path_reference_count_in_pre_p2_36c_repo"] == 0
    assert fresh["selected_git_blob_id_reference_count_in_pre_p2_36c_repo"] == 0
    assert fresh["exact_byte_sha256_not_yet_bound"] is True
    assert fresh["attack_event_contents_parsed_for_selection"] is False

    policy = attack["selection_policy"]
    assert policy["selected_fixture_count"] == 2
    assert policy["all_selector_matches_selected"] is True
    assert policy["post_execution_fixture_replacement_allowed"] is False

    rows = attack["datasets"]
    assert [row["source_path"] for row in rows] == [
        "Demo evtx Files/PtH_02.evtx",
        "Demo evtx Files/lazagneProject.evtx",
    ]
    assert [row["size_bytes"] for row in rows] == [1_118_208, 10_555_392]
    assert [row["git_blob_sha1"] for row in rows] == [
        "d94902a0386400a6d5bdfb86919aa676ee7ade5a",
        "c865ffc64c9861ecb0c1875466d2661506ab8f90",
    ]


def test_p2_36c_benign_exact_asset_is_unused_candidate() -> None:
    benign = _load()["benign_revalidation"]
    assert benign["source"]["repository"] == "NextronSystems/evtx-baseline"
    assert benign["source"]["release_tag"] == "v0.8.5"
    assert benign["source"]["source_family_previously_used_by_breachscope"] is True
    assert benign["freshness_evidence"] == {
        "selected_asset_name_reference_count_in_pre_p2_36c_repo": 0,
        "selected_asset_sha256_reference_count_in_pre_p2_36c_repo": 0,
        "archive_inventory_before_merge": False,
        "event_contents_parsed_for_selection": False,
    }
    assert benign["archive"] == {
        "asset_name": "win7-x86.tgz",
        "size_bytes": 11_109_250,
        "sha256": (
            "e755f3cd48f8a3dc8877c46622339cd44fa0929981fcfd79ada63c2bafb62b9f"
        ),
        "digest_source": "GITHUB_RELEASE_V0_8_5_ASSET_METADATA",
    }


def test_p2_36c_benign_member_size_gate_is_pre_scoring_and_fail_closed() -> None:
    benign = _load()["benign_revalidation"]
    gate = benign["metadata_only_execution_eligibility_gate"]
    assert gate["evaluated_after_source_preregistration_merge"] is True
    assert gate["evaluated_before_execution_contract_merge"] is True
    assert gate["event_contents_may_not_be_parsed_for_gate"] is True
    assert gate["maximum_selected_evtx_member_size_bytes"] == 128 * 1024 * 1024
    assert gate["comparison"] == "EACH_SELECTED_MEMBER_SIZE_LE_MAXIMUM"
    assert gate["oversize_member_policy"] == "REJECT_ENTIRE_ARCHIVE_BEFORE_SCORING"
    assert gate["oversize_member_may_not_be_dropped"] is True
    assert gate["detector_run_allowed_if_gate_fails"] is False
    assert gate["same_analysis_id_detector_retry_allowed_if_gate_fails"] is False
    assert (
        benign["member_selection_policy"]["post_inventory_member_dropping_allowed"]
        is False
    )


def test_p2_36c_current_evidence_still_has_no_fresh_revalidation() -> None:
    current = yaml.safe_load(CURRENT.read_text(encoding="utf-8"))
    validation = current["current_rulepack_validation"]
    assert validation["current_revalidation_id"] == "NOT_RUN"
    assert validation["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert validation["fresh_benign_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert validation["fresh_current_rulepack_performance_available"] is False


def test_p2_36c_execution_gate_prevents_premature_scoring() -> None:
    row = _load()
    gate = row["execution_gate"]
    assert gate["source_preregistration_must_be_merged_before_exact_byte_binding"] is True
    assert gate["separate_execution_contract_required"] is True
    assert gate["execution_contract_must_bind_attack_sha256_after_source_download"] is True
    assert gate["execution_contract_must_bind_benign_inventory_after_archive_download"] is True
    assert gate["execution_contract_must_assert_benign_member_size_gate_passed"] is True
    assert gate["detector_must_not_run_before_execution_contract_merge"] is True
    assert gate["source_or_fixture_selection_must_not_depend_on_detector_output"] is True
    assert row["execution_state_at_preregistration"] == {
        "source_contract_merged": False,
        "benign_metadata_size_gate_evaluated": False,
        "execution_contract_merged": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }


def test_p2_36c_claim_boundary_remains_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["attack_repository_previously_used_by_breachscope"] is False
    assert claim["attack_author_overlap_with_prior_candidate"] is True
    assert claim["benign_source_family_previously_used_by_breachscope"] is True
    assert claim["combined_independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_fraction_is_event_level_recall"] is False
    assert claim["benign_flagged_events_are_confirmed_false_positives"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
