from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_21_a1d00f7"
MEASUREMENT = RESULT_DIR / "measurement.json"
DOWNLOAD = RESULT_DIR / "download-verification.json"
RECORD = RESULT_DIR / "result.yaml"
P17C = ROOT / "external_baseline" / "results" / "p2_17c_b842066" / "measurement.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stored_text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_p2_21_raw_measurement_is_sealed_exactly() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    measurement = json.loads(MEASUREMENT.read_text(encoding="utf-8"))

    assert record["analysis_class"] == "independent_one_pass_external_holdout"
    assert record["artifacts"]["measurement"]["original_sha256"] == "451a67ddd223c11c179abe9b97e27cc32a5a93fd54af4e63f0925d7ba1200f9b"
    assert record["artifacts"]["measurement"]["stored_sha256"] == _stored_text_sha256(MEASUREMENT)
    assert _stored_text_sha256(MEASUREMENT) == "16accdcd1730194b7d93765126f20bc66e4eefd09313f4439a98c09f76c6d070"
    assert record["artifacts"]["download_verification"]["original_sha256"] == "82f01164171053c21d6a90e8a5eb83d5b712af59c150e461a0315143c4089a3b"
    assert record["artifacts"]["download_verification"]["stored_sha256"] == _stored_text_sha256(DOWNLOAD)
    assert _stored_text_sha256(DOWNLOAD) == "f3fea91a3c48c15ab6732df09b1f979fbce2ef78a67e1d94deb57e9be6e14edf"

    assert measurement["status"] == "completed"
    assert measurement["binding_sha256"] == "5166d18d8669e3e9a1d37dca5ab5d08cf0839ec7ecd62ead245995a996e41bdd"
    assert measurement["runner_sha256"] == "f825b99c95f4baa70d4518e3f5d8f5a538f5886091d4c3e2dd3723c44a6996f4"
    assert measurement["frozen_state"]["repo_commit"] == "a1d00f749ec8e644b2ffee716595c6000c22ceea"
    assert measurement["frozen_state"]["rules_tree_sha256"] == "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
    assert measurement["rule_count"] == 68


def test_p2_21_independent_result_remains_four_of_eight() -> None:
    measurement = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    summary = measurement["summary"]

    assert summary["dataset_count"] == 8
    assert summary["hits"] == 4
    assert summary["misses_or_errors"] == 4
    assert summary["path_label_dataset_hit_rate"] == 0.5

    rows = {row["technique_id"]: row for row in measurement["datasets"]}
    assert {tech for tech, row in rows.items() if row["dataset_status"] == "HIT"} == {
        "T1053.005",
        "T1070.001",
        "T1003",
        "T1490",
    }
    assert {tech for tech, row in rows.items() if row["dataset_status"] == "MISS"} == {
        "T1047",
        "T1543.003",
        "T1482",
        "T1021.006",
    }
    assert rows["T1021.006"]["events"] == 0
    assert rows["T1021.006"]["parse_errors"] == 29
    assert all(row["source_verification"]["size_match"] for row in rows.values())
    assert all(row["source_verification"]["git_blob_match"] for row in rows.values())


def test_p2_21_result_record_preserves_claim_boundaries() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    boundary = record["evidence_boundary"]

    assert record["execution"]["one_pass"] is True
    assert record["execution"]["permanent_lock_acquired"] is True
    assert record["execution"]["rerun_allowed"] is False
    assert boundary["p2_21_result_is_independent_one_pass"] is True
    assert boundary["p2_21_result_must_not_be_replaced_by_posthoc_reruns"] is True
    assert boundary["p2_17c_independent_result_remains_1_of_5"] is True
    assert boundary["p2_20_five_of_five_remains_posthoc_only"] is True
    assert boundary["detection_precision"] == "NOT_CLAIMED"
    assert boundary["detection_recall"] == "NOT_CLAIMED"
    assert boundary["false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["path_label_dataset_hit_rate_is_event_level_recall"] is False


def test_p2_17c_sealed_independent_result_is_not_rewritten() -> None:
    prior = json.loads(P17C.read_text(encoding="utf-8"))
    assert prior["summary"]["dataset_count"] == 5
    assert prior["summary"]["hits"] == 1
    assert prior["summary"]["misses_or_errors"] == 4
    assert prior["summary"]["path_label_dataset_hit_rate"] == 0.2


def test_current_evidence_index_includes_p2_21_independent_result() -> None:
    current = yaml.safe_load((ROOT / "external_baseline" / "current_detection_evidence.yaml").read_text(encoding="utf-8"))
    rows = {row["evidence_id"]: row for row in current["external_holdout_evidence"]}
    p21 = rows["p2-21-mdecrevoisier-independent-one-pass"]

    assert p21["class"] == "independent_one_pass_external_holdout"
    assert p21["detector_rule_count"] == 68
    assert p21["dataset_count"] == 8
    assert p21["hits"] == 4
    assert p21["misses_or_errors"] == 4
    assert p21["path_label_dataset_hit_rate"] == 0.5
    assert p21["path_label_dataset_hit_rate_is_event_level_recall"] is False
    assert p21["event_level_ground_truth"] == "NOT_AVAILABLE"
