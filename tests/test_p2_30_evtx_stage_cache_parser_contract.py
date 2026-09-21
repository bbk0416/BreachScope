from __future__ import annotations

import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_30_evtx_stage_cache_parser_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_30_evtx_stage_cache_parser_benchmark.py"
P29C = ROOT / "performance" / "p2_29c_rebenchmark_regression_diagnosis.yaml"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_30_contract_pins_old_and_new_parser_products() -> None:
    row = _load()
    assert row["benchmark_id"] == "p2-30-windows-evtx-stage-cache-parser-v1"
    assert row["status"] == "PREREGISTERED_BEFORE_CANONICAL_EXECUTION"

    old = row["products"]["old"]
    new = row["products"]["new"]
    assert old["repo_commit"] == "7dd6da1069f4d5a29de5fd367fd45fdee24d70d6"
    assert old["parser_git_blob_sha1"] == (
        "42ce35bff10d0541d26e0a5181cfcd1ef9a459cc"
    )
    assert new["repo_commit"] == "d823551bea1d07e18a6d4eb04ddabea741af86e3"
    assert new["parser_git_blob_sha1"] == (
        "34534bf8256ce658c5f05991c05045f7c5066816"
    )


def test_p2_30_contract_pins_exact_sysmon_source() -> None:
    source = _load()["source"]
    assert source["relative_name"] == (
        "Logs_Client/Microsoft-Windows-Sysmon%4Operational.evtx"
    )
    assert source["size_bytes"] == 799_084_544
    assert source["sha256"] == (
        "efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb"
    )
    assert source["record_subset"] == "FIRST_5000_RECORDS"
    assert source["fresh_detection_evaluation"] is False


def test_p2_30_runner_hash_is_frozen() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "883defde8951614e2887121f07fa98aa10b1a22594cf5d62b4b8b3381d6081ed"
    )


def test_p2_30_repeats_stage_measurements_and_separates_timing() -> None:
    measurement = _load()["measurement"]
    assert measurement["record_limit"] == 5000
    assert measurement["repetitions"] == 5

    record = measurement["record_xml_stage"]
    assert record["fresh_child_process_each_repetition"] is True
    assert record["passes_per_repetition"] == 2
    assert record["first_pass_label"] == "NO_IN_PROCESS_PREWARM"
    assert record["second_pass_label"] == "DELIBERATE_WARM"
    assert record["require_identical_xml_digest_between_all_passes"] is True

    parser = measurement["parser_stage"]
    assert parser["materialize_xml_once_after_record_xml_stage"] is True
    assert parser["materialization_is_outside_parser_timing"] is True
    assert parser["load_xml_corpus_is_outside_parser_timing"] is True
    assert parser["fresh_child_process_each_variant_run"] is True
    assert parser["parser_order"] == [
        ["old", "new"],
        ["new", "old"],
        ["old", "new"],
        ["new", "old"],
        ["old", "new"],
    ]
    assert parser["require_identical_normalized_digest_across_all_old_new_runs"] is True


def test_p2_30_does_not_call_no_prewarm_true_cold() -> None:
    cache = _load()["cache_policy"]
    assert cache["exact_source_sha256_verification_before_timing"] is True
    assert cache["source_sha_verification_reads_entire_799mb_file"] is True
    assert cache["true_cold_os_cache"] == "NOT_MEASURED"
    assert cache["os_page_cache_flush_performed"] is False
    assert cache["no_in_process_prewarm_is_true_cold"] is False
    assert cache["between_repetition_os_cache_state"] == "UNCONTROLLED"
    assert cache["cold_cache_speed_claim"] == "NOT_CLAIMED"


def test_p2_30_uses_median_as_primary_without_inferential_stats() -> None:
    measurement = _load()["measurement"]
    assert measurement["primary_summary"]["statistic"] == "median"
    assert measurement["primary_summary"]["inferential_statistics"] is False
    assert measurement["descriptive_summary"] == [
        "mean",
        "min",
        "max",
        "max_over_min_ratio",
    ]


def test_p2_30_protocol_is_first_run_only_and_non_detection() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_canonical_execution"] is True
    assert protocol["permanent_lock_required"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_result_for_better_numbers"] is False
    assert protocol["runner_change_requires_new_benchmark_id"] is True
    assert row["measurement"]["detection_stage_executed"] is False
    assert row["measurement"]["correlation_stage_executed"] is False
    assert row["measurement"]["scenario_stage_executed"] is False
    assert row["measurement"]["report_stage_executed"] is False


def test_p2_30_claim_boundary_stays_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["parser_stage_comparison"] == "NOT_YET_MEASURED"
    assert claim["record_xml_variability"] == "NOT_YET_MEASURED"
    assert claim["causal_explanation_for_p2_29b"] == "NOT_YET_ESTABLISHED"
    assert claim["true_cold_cache_performance"] == "NOT_MEASURED"
    assert claim["general_full_pipeline_speedup"] == "NOT_CLAIMED"
    assert claim["general_full_pipeline_slowdown"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False


def test_p2_30_context_is_exact_p2_29c_record() -> None:
    row = _load()
    context = row["evidence_context"]
    assert context["p2_29c_diagnosis_sha256"] == _sha256(P29C)
    assert context["p2_29c_diagnosis_sha256"] == (
        "2ab2b97379605e063150e7366b1a37223b426b6bcaa14bcf0e8eedd518cdac5d"
    )


def test_p2_30_runner_avoids_pipeline_detection_and_reporting_imports() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert "Pipeline" not in source
    assert "apply_rules" not in source
    assert "correlate" not in source
    assert "infer_scenarios" not in source
    assert "render_html" not in source
    assert "from breachscope.ingest import _extract_from_xml" in source
    assert "from Evtx.Evtx import Evtx" in source
