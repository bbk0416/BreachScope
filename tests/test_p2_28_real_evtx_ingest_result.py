from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "performance" / "p2_28_real_evtx_ingest_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_28_bc61532"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_28_ONE_PASS.lock"


def _load() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_28_canonical_artifact_hashes_are_sealed() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == "bc61532ac642ac4a78c42252b873ddb9a9cfe455"
    assert _sha256(RAW) == "324a77c782623aa53d9f73fdded2f2eef9c1576a585dec18fa529cb7368cbaf8"
    assert _sha256(LOCK) == "e97719573090366a17656fc4de635ede999b5da05ca34fec9884f5ccdf30d6fe"
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert row["canonical_artifacts"]["permanent_lock"]["sha256"] == _sha256(LOCK)


def test_p2_28_raw_result_completed_on_frozen_product_without_detection() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    assert data["status"] == "completed"
    assert data["python"].startswith("3.11.9 ")
    assert data["contract_sha256"] == (
        "990ebf9e6db9ecb4291a9d06af6630d662937a2332cbbd190874500224a74d38"
    )
    assert data["runner_sha256"] == (
        "126b5e33fc9e1ec5485198d4f1a3100672e2ef62c7305596577df3d26c974ac1"
    )
    assert data["frozen_product"] == {
        "repo_commit": "7dd6da1069f4d5a29de5fd367fd45fdee24d70d6",
        "rules_tree_sha256": "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326",
        "rule_file_count": 5,
        "rule_count": 68,
    }
    assert data["claim_boundary"]["detection_executed"] is False
    assert data["claim_boundary"]["detection_accuracy_claimed"] is False


def test_p2_28_source_identity_and_accounting_match_exactly() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    source = data["source_archive"]
    assert source["size_bytes"] == 70_844_052
    assert source["sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert data["extracted"]["evtx_files"] == 352
    assert data["extracted"]["evtx_bytes"] == 876_675_072
    assert data["converted_jsonl"] == {
        "files": 352,
        "bytes": 2_453_341_953,
    }
    assert data["counts"] == {
        "normalized_events": 766_623,
        "expected_reference_events": 766_623,
    }

    accounting = _load()["accounting"]
    assert accounting["exact_source_file_count_match"] is True
    assert accounting["exact_normalized_event_count_match"] is True


def test_p2_28_real_evtx_ingest_metrics_are_exact() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    assert data["stages_seconds"] == {
        "extract_evtx": 3.918071,
        "convert_evtx_dir": 5412.38946,
        "collect_and_normalize": 1324.719248,
        "total_real_evtx_ingest": 6741.026779,
    }
    assert data["throughput_events_per_second"] == 113.725
    assert data["peak_working_set_bytes"] == 4_297_842_688
    assert data["peak_working_set_mb"] == 4098.742

    result = _load()["results"]
    assert result["total_real_evtx_ingest_seconds"] == 6741.026779
    assert result["throughput_events_per_second"] == 113.725
    assert result["peak_working_set_bytes"] == 4_297_842_688
    assert result["peak_working_set_mb"] == 4098.742


def test_p2_28_protocol_preserves_first_run_and_prior_evidence() -> None:
    protocol = _load()["protocol"]
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["first_completed_or_failed_execution_retained_as_canonical"] is True
    assert protocol["duplicate_execution_performed"] is False
    assert protocol["result_replaced_for_better_numbers"] is False
    assert protocol["product_tuned_from_result"] is False
    assert protocol["rules_tuned_from_result"] is False
    assert protocol["accounting_gate_passed"] is True
    assert protocol["detection_stage_executed"] is False
    assert protocol["p2_23b_canonical_result_modified"] is False
    assert protocol["p2_26c_canonical_result_modified"] is False


def test_p2_28_claim_boundary_stays_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["real_evtx_ingest_performance"] == "MEASURED_ON_PINNED_P2_09D_CORPUS"
    assert claim["single_machine_observation"] is True
    assert claim["production_capacity"] == "NOT_CLAIMED"
    assert claim["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
    assert claim["cross_tool_speed_comparison"] == "NOT_CLAIMED"
    assert claim["detection_accuracy"] == "NOT_EVALUATED"
    assert claim["benign_fpr"] == "NOT_EVALUATED"


def test_p2_28_descriptive_breakdown_does_not_turn_into_cross_benchmark_claim() -> None:
    row = _load()
    assert row["descriptive_breakdown"]["convert_evtx_dir_share_percent"] == (
        80.2902827334993
    )
    assert row["descriptive_breakdown"]["collect_and_normalize_share_percent"] == (
        19.65159450377552
    )
    relation = row["relation_to_prior_performance"]
    assert relation["p2_23b_real_evtx_ingest_performance"] == "NOT_MEASURED"
    assert relation["exact_apples_to_apples_comparison_with_p2_23b"] is False
