from __future__ import annotations

import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_30b_evtx_stage_cache_parser_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_30b_evtx_stage_cache_parser_benchmark.py"
OLD_RUNNER = ROOT / "scripts" / "p2_30_evtx_stage_cache_parser_benchmark.py"
FAILURE = ROOT / "performance" / "p2_30_evtx_stage_cache_parser_failure_result.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_30b_uses_new_id_and_seals_predecessor_failure() -> None:
    row = _load()
    assert row["benchmark_id"] == "p2-30b-windows-evtx-stage-cache-parser-v1"
    assert row["status"] == "PREREGISTERED_BEFORE_CANONICAL_EXECUTION"
    failure = row["predecessor_failure"]
    assert failure["benchmark_id"] == "p2-30-windows-evtx-stage-cache-parser-v1"
    assert failure["failure_record_sha256"] == _sha256(FAILURE)
    assert failure["failure_record_sha256"] == (
        "23c53921c8627a9f6e4db81267bf91ea083246043c1c7d846075aeaac7b622eb"
    )
    assert failure["canonical_status"] == "FAILED_CANONICAL"
    assert failure["rerun_under_predecessor_id_allowed"] is False
    assert failure["predecessor_result_replaced"] is False


def test_p2_30b_fix_scope_changes_no_measurement_design() -> None:
    fix = _load()["fix_scope"]
    assert fix["measurement_design_changed"] is False
    assert fix["source_changed"] is False
    assert fix["products_changed"] is False
    assert fix["repetitions_changed"] is False
    assert fix["cache_policy_changed"] is False
    assert fix["parser_order_changed"] is False
    assert fix["benchmark_id_changed"] is True
    assert fix["lock_name_changed"] is True
    assert "measurement.parser_stage.parser_order" in fix["functional_fix"]


def test_p2_30b_runner_is_exact_p2_30_runner_with_only_preregistered_fixes() -> None:
    old = OLD_RUNNER.read_text(encoding="utf-8")
    expected = old
    replacements = [
        (
            'SCHEMA = "breachscope.p2_30_evtx_stage_cache_parser_benchmark.v1"',
            'SCHEMA = "breachscope.p2_30b_evtx_stage_cache_parser_benchmark.v1"',
        ),
        (
            'BENCHMARK_ID = "p2-30-windows-evtx-stage-cache-parser-v1"',
            'BENCHMARK_ID = "p2-30b-windows-evtx-stage-cache-parser-v1"',
        ),
        (
            "Run the preregistered P2-30 EVTX stage/cache/parser benchmark.",
            "Run the preregistered P2-30B EVTX stage/cache/parser benchmark.",
        ),
        ("P2-30 requires Python 3.11", "P2-30B requires Python 3.11"),
        ("P2-30 requires Windows", "P2-30B requires Windows"),
        ("P2_30_ONE_PASS.lock", "P2_30B_ONE_PASS.lock"),
        (
            'order = cfg["parser_order"]',
            'order = cfg["parser_stage"]["parser_order"]',
        ),
    ]
    for before, after in replacements:
        assert expected.count(before) == 1
        expected = expected.replace(before, after)

    assert RUNNER.read_text(encoding="utf-8") == expected


def test_p2_30b_runner_hash_and_corrected_lookup_are_frozen() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "63f9139fcd66a5ee4862a84e2671920c271f490d39d345217cdeb38a14447719"
    )
    source = RUNNER.read_text(encoding="utf-8")
    assert 'order = cfg["parser_stage"]["parser_order"]' in source
    assert 'order = cfg["parser_order"]' not in source
    assert "P2_30B_ONE_PASS.lock" in source


def test_p2_30b_measurement_design_matches_p2_30() -> None:
    row = _load()
    measurement = row["measurement"]
    assert measurement["record_limit"] == 5000
    assert measurement["repetitions"] == 5
    assert measurement["parser_stage"]["parser_order"] == [
        ["old", "new"],
        ["new", "old"],
        ["old", "new"],
        ["new", "old"],
        ["old", "new"],
    ]
    assert measurement["primary_summary"] == {
        "statistic": "median",
        "inferential_statistics": False,
    }
    assert measurement["detection_stage_executed"] is False
    assert measurement["correlation_stage_executed"] is False
    assert measurement["scenario_stage_executed"] is False
    assert measurement["report_stage_executed"] is False


def test_p2_30b_products_source_and_cache_boundary_are_unchanged() -> None:
    row = _load()
    assert row["products"]["old"]["repo_commit"] == (
        "7dd6da1069f4d5a29de5fd367fd45fdee24d70d6"
    )
    assert row["products"]["new"]["repo_commit"] == (
        "d823551bea1d07e18a6d4eb04ddabea741af86e3"
    )
    assert row["source"]["size_bytes"] == 799_084_544
    assert row["source"]["sha256"] == (
        "efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb"
    )
    cache = row["cache_policy"]
    assert cache["true_cold_os_cache"] == "NOT_MEASURED"
    assert cache["no_in_process_prewarm_is_true_cold"] is False
    assert cache["between_repetition_os_cache_state"] == "UNCONTROLLED"


def test_p2_30b_protocol_is_first_run_only_and_new_id_only() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_must_merge_before_canonical_execution"] is True
    assert protocol["permanent_lock_required"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_result_for_better_numbers"] is False
    assert protocol["predecessor_failure_must_remain_sealed"] is True
    assert protocol["p2_30_failed_result_modified"] is False


def test_p2_30b_claim_boundary_remains_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["parser_stage_comparison"] == "NOT_YET_MEASURED"
    assert claim["record_xml_variability"] == "NOT_YET_MEASURED"
    assert claim["causal_explanation_for_p2_29b"] == "NOT_YET_ESTABLISHED"
    assert claim["true_cold_cache_performance"] == "NOT_MEASURED"
    assert claim["general_full_pipeline_speedup"] == "NOT_CLAIMED"
    assert claim["general_full_pipeline_slowdown"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
