from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
AMENDMENT = (
    ROOT
    / "external_baseline"
    / "p2_37_dedale_identity_zero_value_amendment.yaml"
)


def _load() -> dict:
    return yaml.safe_load(AMENDMENT.read_text(encoding="utf-8"))


def test_zero_value_amendment_is_pre_score_and_preserves_blinding() -> None:
    row = _load()
    assert row["status"] == "PRE_SCORING_IDENTITY_SEMANTICS_AMENDMENT"
    reason = row["reason"]
    assert reason["discovered_during"] == "LABEL_BLIND_NORMALIZATION"
    assert reason["labels_read_before_amendment"] is False
    assert reason["detector_run_before_amendment"] is False
    assert reason["result_observed_before_amendment"] is False
    assert reason["source_changed"] is False
    assert reason["scoring_window_changed"] is False
    assert reason["label_mapping_changed"] is False
    assert reason["detector_changed"] is False
    assert reason["rules_changed"] is False


def test_zero_value_amendment_binds_observed_source_failure() -> None:
    evidence = _load()["source_evidence"]
    assert evidence["winlogbeat_sha256"] == (
        "d65572bdf8fa2f19e8fbb0ee925f646649cff53bf5e8f9948578602082fac206"
    )
    assert evidence["member"] == (
        "daily_winlogbeat/D16_H17_2025-01-07T17_winlogbeat_F378.jsonl.bz2"
    )
    assert evidence["source_line"] == 749057
    assert evidence["timestamp"] == "2025-01-07T17:38:06.407Z"
    assert evidence["winlog_channel"] == "Application"
    assert evidence["winlog_record_id"] == 1609
    assert evidence["provider"] == "Dwminit"
    assert evidence["event_code"] == 0


def test_zero_value_amendment_preserves_identity_field_set() -> None:
    row = _load()
    semantics = row["identity_semantics"]
    assert semantics["field_set_changed"] is False
    assert semantics["event_id_source_order"] == [
        "winlog.event_id",
        "event.code",
    ]
    assert semantics["record_id_source"] == "winlog.record_id"
    assert semantics["missing_definition"] == "VALUE_IS_NONE_OR_EMPTY_STRING"
    assert semantics["numeric_zero_is_missing"] is False
    assert semantics["numeric_zero_canonical_text"] == "0"
    assert semantics["fuzzy_matching_added"] is False

    adapter = row["adapter"]
    assert adapter["previous_git_blob_sha1"] == (
        "31bf09ada2f5f511f0eea8ff492732178d848233"
    )
    assert adapter["amended_git_blob_sha1"] == (
        "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
    )
    assert adapter["amended_exact_sha256"] == (
        "4757a3a5efc3627cbab12becb91eb4f46d15f5821a8c91f8898ed4d8f36f2fdb"
    )


def test_zero_value_amendment_invalidates_partial_old_adapter_chunks() -> None:
    prior = _load()["prior_execution"]
    assert prior["window_gate_result_remains_valid"] is True
    assert prior["prior_normalization_final_corpus_created"] is False
    assert prior["prior_normalization_final_identity_map_created"] is False
    assert prior["prior_partial_chunks_canonical"] is False
    assert prior["prior_partial_chunks_may_be_used_with_amended_adapter"] is False
    assert (
        prior[
            "normalization_must_restart_or_use_only_checkpoints_created_by_amended_adapter"
        ]
        is True
    )
