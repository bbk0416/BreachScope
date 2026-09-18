from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_22b_lmd2023_benign_archive_binding.yaml"

MAIN_AT_BINDING = "7311c8146495f5f8601e2581daefdfc88f6e1c41"
RULE_HASH = "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
SOURCE_COMMIT = "d5854e1875e2c2b5564f2cd54ac161abc023bae0"
LFS_SHA256 = "e9f16bcd50b2cae782ceeb2d998697098df3349c8ed3e56c983dc6b096240afe"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_22b_binds_new_lmd_archive_before_observation() -> None:
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_benign_archive_binding"
    assert row["code_under_observation"]["repo_commit"] == MAIN_AT_BINDING
    assert row["code_under_observation"]["rules_tree_sha256"] == RULE_HASH
    assert row["code_under_observation"]["rule_count"] == 68
    assert row["source"]["repository"] == (
        "ChristosSmiliotopoulos/Lateral-Movement-Dataset--LMD_Collections"
    )
    assert row["source"]["pinned_commit"] == SOURCE_COMMIT

    archive = row["source"]["archive"]
    assert archive["path"] == "LMD-2023/LMD-2023.rar"
    assert archive["git_lfs_pointer_blob_sha1"] == "ea44e9f4a04c94bcb9ff951aa2ac5d8bec78d09d"
    assert archive["lfs_object_sha256"] == LFS_SHA256
    assert archive["lfs_object_size_bytes"] == 394944383

    basis = row["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["archive_bytes_downloaded_before_binding"] is False
    assert basis["archive_contents_inspected_before_binding"] is False
    assert basis["source_data_rows_or_events_inspected_before_binding"] is False


def test_p2_22b_uses_only_upstream_explicit_normal_semantics() -> None:
    row = _load()
    ground = row["source_ground_truth"]
    assert ground["evaluation_label_basis"].startswith("use only an upstream path/member explicitly designated Normal")
    facts = "\n".join(ground["readme_supported_facts"])
    assert "separate Normal, EoRS, and EoHT subsets" in facts

    policy = row["protocol"]["normal_subset_selection_policy"]
    assert "1.75M" in policy
    assert "raw/unmodified Windows EVTX" in policy
    assert "explicitly identifies the upstream Normal subset" in policy
    assert "detector behavior" in policy


def test_p2_22b_prohibits_detector_until_exact_member_contract() -> None:
    protocol = _load()["protocol"]
    assert protocol["phase_a_archive_binding_only"] is True
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["no_result_driven_remeasurement"] is True
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
    assert protocol["p2_14e_artifacts_modified"] is False
    assert "ABORT_UNSUPPORTED" in protocol["ambiguous_inventory_policy"]


def test_p2_22b_claims_nothing_before_measurement() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_benign_evaluation"] == "NOT_YET_MEASURED"
    assert claim["benign_false_positive_rate"] == "NOT_YET_MEASURED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_quality"] == "NOT_CLAIMED"
    assert claim["representative_production_population"] == "NOT_CLAIMED"
