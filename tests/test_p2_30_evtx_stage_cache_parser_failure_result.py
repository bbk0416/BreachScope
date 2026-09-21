from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "performance" / "p2_30_evtx_stage_cache_parser_failure_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_30_1c906b05_failed"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_30_ONE_PASS.lock"
CONTRACT = ROOT / "performance" / "p2_30_evtx_stage_cache_parser_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_30_evtx_stage_cache_parser_benchmark.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_30_failed_canonical_artifacts_are_sealed() -> None:
    row = _load()
    assert row["status"] == "FAILED_CANONICAL"
    assert row["contract_merge_commit"] == (
        "1c906b05f7bab67a77a10c176aa7ba7573addb92"
    )
    assert _sha256(RAW) == (
        "00aa87ed62f48601cc37bb25afdbf001dc7df8053f5bea6068ba710b934a2638"
    )
    assert _sha256(LOCK) == (
        "1ff840cf259c6fd7b4bda81f3b04c5cac890a3fb9c687ca061d28f614a87d42d"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert row["canonical_artifacts"]["permanent_lock"]["sha256"] == _sha256(LOCK)


def test_p2_30_raw_result_is_failed_with_exact_preflight_identity() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "failed"
    assert raw["error"] == "KeyError: 'parser_order'"
    assert raw["contract_sha256"] == _sha256(CONTRACT)
    assert raw["runner_sha256"] == _sha256(RUNNER)
    assert raw["products"]["old"]["repo_commit"] == (
        "7dd6da1069f4d5a29de5fd367fd45fdee24d70d6"
    )
    assert raw["products"]["new"]["repo_commit"] == (
        "d823551bea1d07e18a6d4eb04ddabea741af86e3"
    )
    assert raw["source"]["size_bytes"] == 799_084_544
    assert raw["source"]["sha256"] == (
        "efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb"
    )


def test_p2_30_failure_is_runner_contract_path_bug() -> None:
    failure = _load()["failure"]
    assert failure["exception"] == "KeyError: 'parser_order'"
    assert failure["class"] == "RUNNER_CONTRACT_PATH_BUG"
    assert failure["contract_location"] == "measurement.parser_stage.parser_order"
    assert failure["runner_location_used"] == "measurement.parser_order"
    assert failure["benchmark_measurement_completed"] is False
    assert failure["parser_comparison_completed"] is False
    assert failure["canonical_performance_result_available"] is False
    assert failure["partial_timing_reconstruction_allowed"] is False


def test_p2_30_failure_cannot_be_rerun_under_same_id() -> None:
    protocol = _load()["protocol"]
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["duplicate_execution_under_same_benchmark_id_allowed"] is False
    assert protocol["rerun_under_same_benchmark_id_performed"] is False
    assert protocol["replace_failure_for_better_result"] is False
    assert protocol["runner_fix_requires_new_benchmark_id"] is True


def test_p2_30_failure_makes_no_performance_claim() -> None:
    claim = _load()["claim_boundary"]
    assert claim["parser_stage_comparison"] == "NOT_MEASURED"
    assert claim["record_xml_variability"] == "NOT_SEALED_AS_RESULT"
    assert claim["causal_explanation_for_p2_29b"] == "NOT_ESTABLISHED"
    assert claim["true_cold_cache_performance"] == "NOT_MEASURED"
    assert claim["general_full_pipeline_speedup"] == "NOT_CLAIMED"
    assert claim["general_full_pipeline_slowdown"] == "NOT_CLAIMED"


def test_p2_30_next_step_uses_new_benchmark_id() -> None:
    nxt = _load()["next_step"]
    assert nxt["benchmark_id"] == "p2-30b-windows-evtx-stage-cache-parser-v1"
    assert "new benchmark ID" in nxt["requirement"]
