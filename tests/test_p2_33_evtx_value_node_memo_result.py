from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "performance" / "p2_33_evtx_value_node_memo_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_33_af3aef0"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_33_ONE_PASS.lock"
CONTRACT = ROOT / "performance" / "p2_33_evtx_value_node_memo_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_33_evtx_value_node_memo_benchmark.py"
P2_32 = ROOT / "performance" / "p2_32_evtx_value_node_profile_diagnosis.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_33_canonical_artifact_hashes_are_sealed() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == (
        "af3aef08d7e810815395980873526e6c0a0757a8"
    )
    assert _sha256(RAW) == (
        "1658d528f72107905380692a666eeddb4d43212dcf5702dc47285d033155d671"
    )
    assert _sha256(LOCK) == (
        "c019592cce94699dbb72e6a6dde1b7b93d17217174a21e0fb9c741131ffe4140"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert row["canonical_artifacts"]["permanent_lock"]["sha256"] == _sha256(LOCK)


def test_p2_33_raw_result_completed_with_exact_frozen_inputs() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["contract_sha256"] == _sha256(CONTRACT)
    assert raw["runner_sha256"] == _sha256(RUNNER)
    assert raw["contract_sha256"] == (
        "5aeff2d6f22cc65c2f17922393ab394b66e0f397e99987461fd863bb8da5f7ed"
    )
    assert raw["runner_sha256"] == (
        "14c9be2f0163c8b0fb1d5250622c4c06982cf87ca43cbef164e7bc96dc26d1fd"
    )
    assert raw["dependency"]["package"] == "python-evtx"
    assert raw["dependency"]["version"] == "0.8.1"
    assert raw["source"]["size_bytes"] == 799_084_544
    assert raw["source"]["sha256"] == (
        "efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb"
    )


def test_p2_33_all_runs_are_exact_and_semantically_identical() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    runs = raw["runs"]
    assert len(runs) == 10
    assert sum(row["variant"] == "stock" for row in runs) == 5
    assert sum(row["variant"] == "candidate" for row in runs) == 5
    assert all(row["records"] == 5000 for row in runs)
    assert {row["xml_digest_sha256"] for row in runs} == {
        "892861e093f0ee24b48132eae32d897a6cb84b3e2cc338ce3c9a0013baa58c58"
    }
    assert raw["xml_digest_sha256"] == (
        "892861e093f0ee24b48132eae32d897a6cb84b3e2cc338ce3c9a0013baa58c58"
    )


def test_p2_33_timing_summary_is_exact() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    stock = raw["time_summary_seconds"]["stock"]
    candidate = raw["time_summary_seconds"]["candidate"]
    comparison = raw["comparison"]

    assert stock["median"] == 52.72847089999959
    assert stock["mean"] == 53.88314191999998
    assert stock["min"] == 49.36438610000005
    assert stock["max"] == 59.61860990000059

    assert candidate["median"] == 47.87334229999942
    assert candidate["mean"] == 48.99986455999933
    assert candidate["min"] == 43.80499950000012
    assert candidate["max"] == 53.38920449999932

    assert comparison["stock_over_candidate_median_ratio"] == 1.1014161194256167
    assert comparison["candidate_median_change_percent"] == -9.207793279664797


def test_p2_33_memory_cost_is_recorded_not_hidden() -> None:
    row = _load()
    memory = row["memory"]
    assert memory["stock_peak_rss_bytes"]["median"] == 47_116_288.0
    assert memory["candidate_peak_rss_bytes"]["median"] == 47_751_168.0
    assert memory["median_peak_difference_bytes"] == 634_880
    assert memory["candidate_median_peak_change_percent"] == 1.3474745718508214
    assert "slightly more peak RSS" in memory["interpretation"]


def test_p2_33_result_does_not_auto_authorize_product_patch() -> None:
    row = _load()
    decision = row["decision"]
    assert decision["product_code_change"] is False
    assert decision["product_monkey_patch_python_evtx"] == "NO"
    assert decision["dependency_fork_or_vendor_change"] == "DEFERRED"
    assert decision["upstream_contribution"] == "DEFERRED"
    assert decision["adoption_authorized_by_benchmark_alone"] is False

    claim = row["claim_boundary"]
    assert claim["candidate_comparison"] == (
        "MEASURED_AS_PREREGISTERED_REPEATED_DEPENDENCY_LEVEL_OBSERVATION"
    )
    assert claim["candidate_general_speedup"] == "NOT_CLAIMED"
    assert claim["true_cold_cache_performance"] == "NOT_MEASURED"
    assert claim["full_pipeline_speedup"] == "NOT_CLAIMED"
    assert claim["product_adoption"] == "NOT_DECIDED"
    assert claim["statistical_benchmark"] is False


def test_p2_33_preserves_predecessor_and_non_detection_scope() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["duplicate_canonical_execution_performed"] is False
    assert protocol["replace_result_for_better_numbers"] is False
    assert protocol["p2_30b_result_modified"] is False
    assert protocol["p2_31_result_modified"] is False
    assert protocol["p2_32_diagnosis_modified"] is False
    assert protocol["detection_stage_executed"] is False
    assert protocol["breachscope_event_parser_executed"] is False
    assert protocol["correlation_stage_executed"] is False
    assert protocol["scenario_stage_executed"] is False
    assert protocol["report_stage_executed"] is False

    p2_32 = yaml.safe_load(P2_32.read_text(encoding="utf-8"))
    assert p2_32["status"] == "CLOSE_POSTHOC_CANDIDATE_IDENTIFIED"
    assert p2_32["decision"]["product_code_change"] is False

def test_p2_33_lock_is_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "performance/results/p2_33_af3aef0/P2_33_ONE_PASS.lock -text -whitespace"
        in attrs
    )
