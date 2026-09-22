from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "performance" / "p2_34_evtx_value_node_semantic_sweep_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_34_40724bf"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_34_ONE_PASS.lock"
CONTRACT = ROOT / "performance" / "p2_34_evtx_value_node_semantic_sweep_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_34_evtx_value_node_semantic_sweep.py"
P2_33 = ROOT / "performance" / "p2_33_evtx_value_node_memo_result.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def _projection(payload: dict) -> dict:
    return {
        "file_count": payload["file_count"],
        "total_bytes": payload["total_bytes"],
        "path_size_manifest_sha256": payload["path_size_manifest_sha256"],
        "records_per_file_limit": payload["records_per_file_limit"],
        "total_sampled_records": payload["total_sampled_records"],
        "zero_record_files": payload["zero_record_files"],
        "global_xml_digest_sha256": payload["global_xml_digest_sha256"],
        "file_results": payload["file_results"],
    }


def test_p2_34_canonical_artifact_hashes_are_sealed() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == (
        "40724bf58352f090e826421af680b62e1cabf423"
    )
    assert RAW.stat().st_size == 177_568
    assert LOCK.stat().st_size == 116
    assert _sha256(RAW) == (
        "72579d61e447c4809303b5460d985fddef27e959c8d39991949881fd44d2e119"
    )
    assert _sha256(LOCK) == (
        "5b76190379c3dacc6e1d3c5edba75dcb34d91ecf81573b7255ee63314d9f9dcc"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert row["canonical_artifacts"]["permanent_lock"]["sha256"] == _sha256(LOCK)


def test_p2_34_raw_result_completed_with_exact_frozen_inputs() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["contract_sha256"] == _sha256(CONTRACT)
    assert raw["runner_sha256"] == _sha256(RUNNER)
    assert raw["contract_sha256"] == (
        "17360f77464ecd497bf797f0f13fdd20d02a50e342b926915e9d4009b506c5d5"
    )
    assert raw["runner_sha256"] == (
        "e30620f3dca7f95c11b3305ce11600e8a3e299a95bfac295c24a267e6d9936e3"
    )
    assert raw["dependency"]["package"] == "python-evtx"
    assert raw["dependency"]["version"] == "0.8.1"
    assert raw["source"]["archive_size_bytes"] == 70_844_052
    assert raw["source"]["archive_sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert raw["source"]["file_count"] == 352
    assert raw["source"]["total_bytes"] == 876_675_072
    assert raw["source"]["path_size_manifest_sha256"] == (
        "a9b870148219041b787cc1f8e4e7ca1fc2f543c11c45b91e7d51d5c84271fc6e"
    )


def test_p2_34_stock_candidate_semantic_projection_is_exact() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    measurement = raw["measurement"]
    stock = measurement["variants"]["stock"]
    candidate = measurement["variants"]["candidate"]

    assert measurement["semantic_projection_identical"] is True
    assert _projection(stock) == _projection(candidate)
    assert measurement["total_sampled_records"] == 1_827
    assert measurement["zero_record_files"] == 255
    assert measurement["global_xml_digest_sha256"] == (
        "b4c7c01e0ac6e1b7e7871111a41b1173c37b7249da59e6b0b5e324c87ad064cf"
    )
    assert len(stock["file_results"]) == 352
    assert len(candidate["file_results"]) == 352


def test_p2_34_timing_is_descriptive_only_not_a_speed_claim() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = _load()
    stock = raw["measurement"]["variants"]["stock"]
    candidate = raw["measurement"]["variants"]["candidate"]

    assert stock["elapsed_seconds_descriptive_only"] == 26.089332799994736
    assert candidate["elapsed_seconds_descriptive_only"] == 31.65723060000164
    timing = row["descriptive_timing_seconds"]
    assert timing["performance_comparison_allowed"] is False
    assert timing["interpretation"] == (
        "RECORDED_FOR_DIAGNOSTICS_ONLY_NOT_A_PERFORMANCE_COMPARISON"
    )
    assert row["claim_boundary"]["performance_comparison"] == "NOT_EVALUATED"
    assert row["claim_boundary"]["candidate_general_speedup"] == "NOT_CLAIMED"


def test_p2_34_gate_pass_does_not_auto_authorize_product_patch() -> None:
    row = _load()
    decision = row["decision"]
    assert decision["semantic_gate"] == "PASS"
    assert decision["any_semantic_mismatch_observed"] is False
    assert decision["product_code_change"] is False
    assert decision["product_monkey_patch_python_evtx"] == "NO"
    assert decision["adoption_authorized_by_gate_alone"] is False
    assert decision["product_adoption"] == "NOT_DECIDED"

    claim = row["claim_boundary"]
    assert claim["semantic_equivalence_scope"] == (
        "FIRST_UP_TO_25_RECORDS_PER_EACH_OF_352_PINNED_EVTX_FILES"
    )
    assert claim["all_records_semantic_equivalence"] == "NOT_EVALUATED"
    assert claim["product_adoption"] == "NOT_DECIDED"
    assert claim["statistical_benchmark"] is False


def test_p2_34_preserves_predecessor_and_non_detection_scope() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["duplicate_canonical_execution_performed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["product_code_changed_for_gate"] is False
    assert protocol["p2_33_result_modified"] is False
    assert protocol["p2_32_diagnosis_modified"] is False
    assert protocol["p2_30b_result_modified"] is False
    assert protocol["detection_stage_executed"] is False
    assert protocol["breachscope_event_parser_executed"] is False
    assert protocol["correlation_stage_executed"] is False
    assert protocol["scenario_stage_executed"] is False
    assert protocol["report_stage_executed"] is False

    p2_33 = yaml.safe_load(P2_33.read_text(encoding="utf-8"))
    assert p2_33["status"] == "COMPLETED"
    assert _sha256(P2_33) == (
        "35768c31be9fbbcbeb7a1c7d3c7440ad06e999473d20c0ef77a8e6d514ce62f8"
    )


def test_p2_34_lock_is_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "performance/results/p2_34_40724bf/P2_34_ONE_PASS.lock -text -whitespace"
        in attrs
    )
