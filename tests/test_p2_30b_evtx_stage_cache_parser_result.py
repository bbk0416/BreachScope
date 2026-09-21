from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "performance" / "p2_30b_evtx_stage_cache_parser_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_30b_55ba2a7e"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_30B_ONE_PASS.lock"
CONTRACT = ROOT / "performance" / "p2_30b_evtx_stage_cache_parser_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_30b_evtx_stage_cache_parser_benchmark.py"
P2_30_FAILURE = ROOT / "performance" / "p2_30_evtx_stage_cache_parser_failure_result.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_30b_canonical_artifact_hashes_are_sealed() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == (
        "55ba2a7e558e5e8cf54ced9af63e64fb9367cd99"
    )
    assert _sha256(RAW) == (
        "bdfc29e556b2d6ce72675cf54376afd81d62137271e2e9a688d5247200069761"
    )
    assert _sha256(LOCK) == (
        "bd7975ff1c46bffa735d0edef421c545031053784de57bea0313b7fe3e4b4f4f"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert row["canonical_artifacts"]["permanent_lock"]["sha256"] == _sha256(LOCK)


def test_p2_30b_raw_result_completed_with_exact_frozen_inputs() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["contract_sha256"] == _sha256(CONTRACT)
    assert raw["runner_sha256"] == _sha256(RUNNER)
    assert raw["contract_sha256"] == (
        "0300fcea5299255b32b4ac8d78bd3283142a7d0909eee61fa813016a97b33210"
    )
    assert raw["runner_sha256"] == (
        "63f9139fcd66a5ee4862a84e2671920c271f490d39d345217cdeb38a14447719"
    )
    assert raw["products"]["old"] == {
        "repo_commit": "7dd6da1069f4d5a29de5fd367fd45fdee24d70d6",
        "parser_git_blob_sha1": "42ce35bff10d0541d26e0a5181cfcd1ef9a459cc",
    }
    assert raw["products"]["new"] == {
        "repo_commit": "d823551bea1d07e18a6d4eb04ddabea741af86e3",
        "parser_git_blob_sha1": "34534bf8256ce658c5f05991c05045f7c5066816",
    }
    assert raw["source"]["size_bytes"] == 799_084_544
    assert raw["source"]["sha256"] == (
        "efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb"
    )


def test_p2_30b_predecessor_failure_remains_sealed() -> None:
    row = _load()
    predecessor = row["predecessor"]
    assert predecessor["canonical_status"] == "FAILED_CANONICAL"
    assert predecessor["failure_record_sha256"] == _sha256(P2_30_FAILURE)
    assert predecessor["failure_record_sha256"] == (
        "23c53921c8627a9f6e4db81267bf91ea083246043c1c7d846075aeaac7b622eb"
    )
    assert predecessor["predecessor_rerun_performed"] is False
    assert predecessor["predecessor_result_replaced"] is False


def test_p2_30b_record_xml_accounting_and_digest_are_exact() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    runs = raw["record_xml_runs"]
    assert len(runs) == 5

    digests = set()
    for index, run in enumerate(runs, start=1):
        assert run["repetition"] == index
        for label in ("no_in_process_prewarm", "deliberate_warm"):
            assert run[label]["records"] == 5000
            digests.add(run[label]["xml_digest_sha256"])

    materialized = raw["materialized_xml_corpus"]
    assert materialized["records"] == 5000
    assert materialized["xml_corpus_bytes"] == 7_481_758
    digests.add(materialized["xml_digest_sha256"])

    assert digests == {
        "892861e093f0ee24b48132eae32d897a6cb84b3e2cc338ce3c9a0013baa58c58"
    }


def test_p2_30b_record_xml_summary_is_exact_and_not_true_cold() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    no_prewarm = raw["record_xml_summary"]["no_in_process_prewarm"]
    warm = raw["record_xml_summary"]["deliberate_warm"]

    assert no_prewarm["count"] == 5
    assert no_prewarm["median_seconds"] == 64.98229309997987
    assert no_prewarm["mean_seconds"] == 69.08430176000111
    assert no_prewarm["min_seconds"] == 52.03555430000415
    assert no_prewarm["max_seconds"] == 92.69287829997484
    assert no_prewarm["max_over_min_ratio"] == 1.7813373864639979

    assert warm["count"] == 5
    assert warm["median_seconds"] == 67.68253360001836
    assert warm["mean_seconds"] == 64.67857818000485
    assert warm["min_seconds"] == 55.7640415999922
    assert warm["max_seconds"] == 73.61016689997632
    assert warm["max_over_min_ratio"] == 1.320029265955978

    claim = raw["claim_boundary"]
    assert claim["true_cold_os_cache"] == "NOT_MEASURED"
    assert claim["no_in_process_prewarm_is_true_cold"] is False
    assert claim["deliberate_warm_is_same_process_immediate_second_pass"] is True


def test_p2_30b_parser_runs_are_semantically_identical() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    runs = raw["parser_runs"]
    assert len(runs) == 10
    assert sum(row["variant"] == "old" for row in runs) == 5
    assert sum(row["variant"] == "new" for row in runs) == 5
    assert all(row["records"] == 5000 for row in runs)
    assert {row["normalized_digest_sha256"] for row in runs} == {
        "54e65dcddc6154d0ed562e66addb8152fce8c262a9c150f7b423420e9e925e66"
    }


def test_p2_30b_parser_summary_and_comparison_are_exact() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    old = raw["parser_summary"]["old"]
    new = raw["parser_summary"]["new"]
    comparison = raw["comparison"]

    assert old == {
        "count": 5,
        "median_seconds": 3.221731999947224,
        "mean_seconds": 3.5307886200025678,
        "min_seconds": 2.5258124000392854,
        "max_seconds": 4.85356060002232,
        "max_over_min_ratio": 1.9215839624300006,
    }
    assert new == {
        "count": 5,
        "median_seconds": 2.4767881999723613,
        "mean_seconds": 2.8028352200170046,
        "min_seconds": 2.146005700051319,
        "max_seconds": 3.869569100032095,
        "max_over_min_ratio": 1.803149497664223,
    }
    assert comparison["old_over_new_parser_median_ratio"] == 1.300770086026401
    assert comparison["new_parser_median_change_percent"] == -23.12246332056998
    assert comparison["normalized_output_digest_sha256"] == (
        "54e65dcddc6154d0ed562e66addb8152fce8c262a9c150f7b423420e9e925e66"
    )


def test_p2_30b_result_does_not_overclaim_full_pipeline_or_causality() -> None:
    row = _load()
    assert row["parser_stage"]["comparison"]["observed_direction"] == (
        "NEW_PARSER_LOWER_MEDIAN_IN_REPEATED_STAGE_LEVEL_OBSERVATION"
    )
    claim = row["claim_boundary"]
    assert claim["parser_stage_comparison"] == (
        "MEASURED_AS_REPEATED_STAGE_LEVEL_OBSERVATION"
    )
    assert claim["parser_stage_general_speedup"] == "NOT_CLAIMED"
    assert claim["causal_explanation_for_p2_29b"] == "NOT_ESTABLISHED"
    assert claim["full_pipeline_speedup"] == "NOT_CLAIMED"
    assert claim["full_pipeline_slowdown"] == "NOT_CLAIMED"
    assert claim["true_cold_cache_performance"] == "NOT_MEASURED"
    assert claim["statistical_benchmark"] is False
    assert claim["detection_accuracy"] == "NOT_EVALUATED"
    assert claim["benign_fpr"] == "NOT_EVALUATED"


def test_p2_30b_protocol_preserves_first_run_and_non_detection_scope() -> None:
    protocol = _load()["protocol"]
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["first_completed_or_failed_execution_retained_as_canonical"] is True
    assert protocol["duplicate_canonical_execution_performed"] is False
    assert protocol["replace_result_for_better_numbers"] is False
    assert protocol["p2_30_failed_result_modified"] is False
    assert protocol["p2_28_result_modified"] is False
    assert protocol["p2_29b_result_modified"] is False
    assert protocol["p2_29c_diagnosis_modified"] is False
    assert protocol["detection_stage_executed"] is False
    assert protocol["correlation_stage_executed"] is False
    assert protocol["scenario_stage_executed"] is False
    assert protocol["report_stage_executed"] is False
