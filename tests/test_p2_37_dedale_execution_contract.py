from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_37_dedale_execution_contract.yaml"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_37_execution_contract_binds_exact_source_and_window() -> None:
    row = _load()
    assert row["status"] == "PRE_NORMALIZATION_EXECUTION_CONTRACT"

    source = row["source_bytes"]
    assert source["winlogbeat"]["sha256"] == (
        "d65572bdf8fa2f19e8fbb0ee925f646649cff53bf5e8f9948578602082fac206"
    )
    assert source["winlogbeat"]["provider_md5_match"] is True
    assert source["labels"]["sha256"] == (
        "729ac223a89c70f771861920b6b9ee3ab1bb5569e12ec54c04f380aadf574dc7"
    )
    assert source["labels"]["provider_md5_match"] is True

    adapter = row["frozen_adapter"]
    assert adapter["git_blob_sha1"] == "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
    assert adapter["local_exact_sha256"] == (
        "4757a3a5efc3627cbab12becb91eb4f46d15f5821a8c91f8898ed4d8f36f2fdb"
    )

    amendment = row["identity_zero_value_amendment"]
    assert amendment["previous_adapter_git_blob_sha1"] == (
        "31bf09ada2f5f511f0eea8ff492732178d848233"
    )
    assert amendment["current_adapter_git_blob_sha1"] == (
        "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
    )
    assert amendment["labels_read_before_amendment"] is False
    assert amendment["detector_run_before_amendment"] is False
    assert amendment["result_observed_before_amendment"] is False
    assert amendment["prior_partial_old_adapter_chunks_canonical"] is False

    gate = row["window_gate"]
    assert gate["verifier_git_blob_sha1"] == (
        "13dfc222fcc8868306323a63758b0856f68d0e44"
    )
    assert gate["local_result_artifact_sha256"] == (
        "0536327c25f04cb75fa3db216831fc92258c84101b041787b33d162788758563"
    )
    assert gate["local_result_artifact_size_bytes"] == 5777
    result = gate["result"]
    assert result["status"] == "PASS"
    assert result["returncode"] == 0
    assert result["detection_rules_executed"] is False
    assert result["labels_read"] is False
    assert result["distinct_utc_dates"] == 28
    assert result["sentinel_count"] == 28
    assert result["sentinel_rows"] == 2538961
    assert result["test_window_start"] == "2025-01-06T00:00:00+00:00"
    assert result["test_window_end_exclusive"] == "2025-01-20T00:00:00+00:00"


def test_p2_37_execution_order_keeps_detector_off_until_final_score() -> None:
    order = _load()["execution_order"]
    assert [item["action"] for item in order] == [
        "NORMALIZE_LABEL_BLIND",
        "CREATE_EVALUATOR_INDEX_WITHOUT_DETECTION",
        "BIND_PROVIDER_LABELS_POST_INDEX",
        "HASH_AND_BIND_EXECUTION_ARTIFACTS",
        "MERGE_EXECUTION_ARTIFACT_BINDING",
        "RUN_SINGLE_CANONICAL_SCORE",
    ]

    for item in order[:5]:
        assert item["detector_may_run"] is False
    assert order[0]["labels_may_be_read"] is False
    assert order[1]["labels_may_be_read"] is False
    assert order[2]["labels_may_be_read"] is True
    assert order[5]["detector_may_run"] is True
    assert order[5]["maximum_canonical_scoring_runs"] == 1


def test_p2_37_execution_state_is_still_pre_normalization_and_pre_detection() -> None:
    state = _load()["execution_state_at_contract"]
    assert state == {
        "exact_source_bytes_bound": True,
        "window_gate_passed": True,
        "normalized_corpus_created": False,
        "provider_identity_map_created": False,
        "evaluator_index_created": False,
        "labels_read_for_scoring": False,
        "evaluator_labels_created": False,
        "execution_artifact_binding_merged": False,
        "detector_run": False,
        "result_observed": False,
    }


def test_p2_37_execution_contract_preserves_nonclaims() -> None:
    claim = _load()["claim_boundary"]
    assert claim["evaluation_class"] == "external_baseline"
    assert claim["final_blind_holdout"] is False
    assert claim["provider_labels_are_independent_adjudication"] is False
    assert claim["representative_production_population"] is False
    assert claim["successful_metrics_may_be_named_dedale_holdout_metrics"] is True
    assert claim["successful_metrics_may_be_named_production_metrics"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_precision"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
