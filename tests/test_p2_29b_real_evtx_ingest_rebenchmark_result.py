from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "performance" / "p2_29b_real_evtx_ingest_rebenchmark_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_29b_32499723"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_29B_ONE_PASS.lock"


def _load() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_29b_canonical_artifact_hashes_are_sealed() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == "32499723d13032c1a88f7cffeae9ef98ccd1fd5c"
    assert _sha256(RAW) == "4c2d96542102e8c6f9ef5072a7143beb29e4b5a6e0acfc1af0d954f8f56e6503"
    assert _sha256(LOCK) == "d63c40863bcdedb5be52ef9b833cac6fafd4dcbc3f3852b1dcbff5c0c3875cf3"
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert row["canonical_artifacts"]["permanent_lock"]["sha256"] == _sha256(LOCK)


def test_p2_29b_raw_result_completed_on_exact_product_and_environment() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    assert data["status"] == "completed"
    assert data["contract_sha256"] == (
        "0a7c475189c8eb18319cdf19385a14057455adeb8b027ecc63ec29ce8b003b65"
    )
    assert data["runner_sha256"] == (
        "36239dd828aa7856d9472ba43195a55e90fdc1893ea628619895fb6c097f2383"
    )
    assert data["frozen_product"]["repo_commit"] == (
        "5bef1e71440a312a278a5e686f63203391dcdf7b"
    )
    assert data["environment_matches_p2_28"] is True
    assert data["environment"] == data["baseline"]["environment"]


def test_p2_29b_source_and_accounting_match_exactly() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    assert data["source_archive"]["size_bytes"] == 70_844_052
    assert data["source_archive"]["sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert data["extracted"]["evtx_files"] == 352
    assert data["converted_jsonl"] == {
        "files": 352,
        "bytes": 2_453_341_953,
    }
    assert data["counts"] == {
        "normalized_events": 766_623,
        "expected_reference_events": 766_623,
    }


def test_p2_29b_after_metrics_are_exact() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    assert data["stages_seconds"] == {
        "extract_evtx": 12.486581,
        "convert_evtx_dir": 9334.587379,
        "collect_and_normalize": 1380.083951,
        "total_real_evtx_ingest": 10727.157911,
    }
    assert data["throughput_events_per_second"] == 71.466
    assert data["peak_working_set_bytes"] == 5_005_115_392
    assert data["peak_working_set_mb"] == 4773.25


def test_p2_29b_baseline_is_sealed_p2_28_without_rerun() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    baseline = data["baseline"]
    assert baseline["raw_result_sha256"] == (
        "324a77c782623aa53d9f73fdded2f2eef9c1576a585dec18fa529cb7368cbaf8"
    )
    assert baseline["stages_seconds"]["total_real_evtx_ingest"] == 6741.026779
    assert baseline["throughput_events_per_second"] == 113.725
    assert baseline["peak_working_set_bytes"] == 4_297_842_688

    protocol = _load()["protocol"]
    assert protocol["baseline_rerun_performed"] is False
    assert protocol["baseline_result_modified"] is False


def test_p2_29b_comparison_records_observed_regression_without_generalizing() -> None:
    data = json.loads(RAW.read_text(encoding="utf-8"))
    comparison = data["comparison"]
    assert comparison["observed_total_speedup_ratio"] == 0.628408
    assert comparison["observed_total_time_reduction_percent"] == -59.132403
    assert comparison["observed_convert_speedup_ratio"] == 0.579821
    assert comparison["observed_collect_speedup_ratio"] == 0.959883
    assert comparison["observed_throughput_ratio"] == 0.628411
    assert comparison["observed_throughput_change_percent"] == -37.158936
    assert comparison["observed_peak_working_set_change_bytes"] == 707_272_704
    assert comparison["observed_peak_working_set_change_percent"] == 16.456459

    row = _load()
    assert row["comparison"]["observed_direction"] == (
        "REGRESSION_IN_THIS_SINGLE_PAIRED_OBSERVATION"
    )
    claim = row["claim_boundary"]
    assert claim["general_speedup"] == "NOT_CLAIMED"
    assert claim["causal_attribution_to_single_parse_refactor"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False


def test_p2_29b_protocol_preserves_first_run_and_no_detection() -> None:
    protocol = _load()["protocol"]
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["first_completed_or_failed_after_execution_retained_as_canonical"] is True
    assert protocol["duplicate_after_execution_performed"] is False
    assert protocol["after_result_replaced_for_better_numbers"] is False
    assert protocol["product_tuned_from_result"] is False
    assert protocol["accounting_gate_passed"] is True
    assert protocol["detection_stage_executed"] is False
    assert protocol["correlation_stage_executed"] is False
    assert protocol["scenario_stage_executed"] is False
    assert protocol["report_stage_executed"] is False
