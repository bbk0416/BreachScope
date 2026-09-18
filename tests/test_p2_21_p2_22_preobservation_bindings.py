from __future__ import annotations

import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
P21 = ROOT / "external_baseline" / "p2_21_independent_attack_binding.yaml"
P22 = ROOT / "external_baseline" / "p2_22_cerberus_benign_source_binding.yaml"
RUNNER = ROOT / "scripts" / "p2_21_independent_one_pass.py"

CURRENT_COMMIT = "a1d00f749ec8e644b2ffee716595c6000c22ceea"
CURRENT_RULE_HASH = "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8-sig"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_21_attack_binding_is_frozen_before_observation() -> None:
    binding = _load(P21)

    assert binding["analysis_class"] == "pre_observation_external_holdout_binding"
    assert binding["code_under_observation"] == {
        "repo_commit": CURRENT_COMMIT,
        "rules_tree_sha256": CURRENT_RULE_HASH,
        "rule_count": 68,
    }
    assert binding["source"]["repository"] == "mdecrevoisier/EVTX-to-MITRE-Attack"
    assert binding["source"]["pinned_commit"] == "474856008f037ccd42753f02a631b42690195829"
    assert binding["runner"]["sha256"] == _sha256(RUNNER)

    datasets = binding["datasets"]
    assert len(datasets) == 8
    assert len({row["technique_id"] for row in datasets}) == 8
    assert len({row["source_path"] for row in datasets}) == 8
    assert all(row["size_bytes"] > 0 for row in datasets)
    assert all(len(row["git_blob_sha1"]) == 40 for row in datasets)

    policy = binding["selection_policy"]
    assert policy["detector_results_consulted_before_selection"] is False
    assert policy["selected_evtx_bytes_downloaded_before_binding"] is False
    assert policy["selected_evtx_contents_inspected_before_binding"] is False

    protocol = binding["protocol"]
    assert protocol["one_pass_measurement_planned"] is True
    assert protocol["no_result_driven_remeasurement"] is True
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
    assert protocol["p2_14e_artifacts_modified"] is False


def test_p2_21_claim_boundary_does_not_overstate_dataset_hit_rate() -> None:
    claim = _load(P21)["claim_boundary"]
    assert claim["event_level_ground_truth"] == "NOT_AVAILABLE"
    assert claim["detection_precision"] == "NOT_CLAIMED"
    assert claim["detection_recall"] == "NOT_CLAIMED"
    assert claim["false_positive_rate"] == "NOT_CLAIMED"
    assert claim["path_label_dataset_hit_rate"] == "MEASURABLE_AFTER_ONE_PASS"
    assert claim["path_label_dataset_hit_rate_is_event_level_recall"] is False


def test_p2_22_is_source_binding_only_and_detector_is_prohibited() -> None:
    binding = _load(P22)

    assert binding["analysis_class"] == "pre_observation_external_benign_source_binding"
    assert binding["code_under_observation"] == {
        "repo_commit": CURRENT_COMMIT,
        "rules_tree_sha256": CURRENT_RULE_HASH,
        "rule_count": 68,
    }
    assert binding["source"]["repository"] == "bazz-066/cerberus-trace"
    assert binding["source"]["pinned_commit"] == "69933c61491fa966068c44c11172889898fbe789"
    assert binding["source"]["archive"]["git_blob_sha1"] == "731b33a5b46bfc3090e9d78b7247e36593d5c71b"
    assert binding["source"]["label_table"]["git_blob_sha1"] == "9f86c4a70f1545546cdc5208f1fe9de8832318cc"

    basis = binding["selection_basis"]
    assert basis["archive_bytes_downloaded_before_binding"] is False
    assert basis["archive_contents_inspected_before_binding"] is False
    assert basis["label_table_bytes_downloaded_before_binding"] is False
    assert basis["label_table_contents_inspected_before_binding"] is False

    protocol = binding["protocol"]
    assert protocol["phase_a_source_binding_only"] is True
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
    assert protocol["p2_14e_artifacts_modified"] is False
    assert "ABORT_UNSUPPORTED" in protocol["unsupported_policy"]


def test_p2_22_does_not_claim_fpr_before_label_contract() -> None:
    claim = _load(P22)["claim_boundary"]
    assert claim["fresh_benign_evaluation"] == "NOT_YET_MEASURED"
    assert claim["benign_false_positive_rate"] == "NOT_YET_MEASURED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
