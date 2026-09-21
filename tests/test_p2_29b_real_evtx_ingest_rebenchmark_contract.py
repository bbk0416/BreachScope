from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_29b_real_evtx_ingest_rebenchmark_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_29b_real_evtx_ingest_rebenchmark.py"
BASELINE = ROOT / "performance" / "results" / "p2_28_bc61532" / "result.json"
MAINTENANCE = ROOT / "external_baseline" / "p2_29_single_parse_parser_maintenance.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_29b_contract_pins_sealed_p2_28_baseline() -> None:
    row = _load()
    baseline = row["baseline"]
    assert baseline["benchmark_id"] == "p2-28-windows-real-evtx-ingest-nextron-win10-v1"
    assert baseline["raw_result_sha256"] == _sha256(BASELINE)
    assert baseline["raw_result_sha256"] == (
        "324a77c782623aa53d9f73fdded2f2eef9c1576a585dec18fa529cb7368cbaf8"
    )
    assert baseline["rerun_allowed"] is False
    assert baseline["result_replacement_allowed"] is False

    raw = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["counts"]["normalized_events"] == 766623
    assert raw["stages_seconds"]["total_real_evtx_ingest"] == 6741.026779
    assert raw["throughput_events_per_second"] == 113.725
    assert raw["peak_working_set_bytes"] == 4297842688
    assert raw["environment"] == baseline["environment"]


def test_p2_29b_contract_pins_merged_single_parse_product() -> None:
    row = _load()
    product = row["product"]
    assert product["repo_commit"] == "5bef1e71440a312a278a5e686f63203391dcdf7b"
    assert product["parser_git_blob_sha1"] == (
        "34534bf8256ce658c5f05991c05045f7c5066816"
    )
    assert product["rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    maintenance = yaml.safe_load(MAINTENANCE.read_text(encoding="utf-8"))
    assert maintenance["equivalence"]["combined_current_revalidation_sources"][
        "records_compared"
    ] == 2093
    assert maintenance["equivalence"]["combined_current_revalidation_sources"][
        "mismatches"
    ] == 0


def test_p2_29b_runner_hash_and_source_are_frozen() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "36239dd828aa7856d9472ba43195a55e90fdc1893ea628619895fb6c097f2383"
    )
    source = RUNNER.read_text(encoding="utf-8")
    assert 'BENCHMARK_ID = "p2-29b-windows-real-evtx-single-parse-rebenchmark-v1"' in source
    assert "P2_29B_ONE_PASS.lock" in source
    assert "load_and_verify_baseline" in source
    assert "verify_environment_matches_baseline" in source
    assert "comparison_metrics" in source


def test_p2_29b_source_and_accounting_are_exactly_same_as_p2_28() -> None:
    row = _load()
    source = row["source"]
    assert source["asset_size_bytes"] == 70844052
    assert source["asset_sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert source["expected_source_evtx_files_total"] == 352
    assert source["expected_reference_events"] == 766623
    assert source["source_role"] == "DEVELOPMENT_PERFORMANCE_CORPUS"
    assert source["fresh_detection_evaluation"] is False

    gate = row["accounting_gate"]
    assert gate["exact_source_evtx_files_required"] == 352
    assert gate["exact_normalized_events_required"] == 766623


def test_p2_29b_requires_exact_environment_match_and_single_after_run() -> None:
    row = _load()
    gate = row["environment_gate"]
    assert gate["exact_match_to_p2_28_required"] is True
    assert gate["fields"] == [
        "platform",
        "machine",
        "processor",
        "logical_cpu_count",
        "total_physical_memory_bytes",
    ]
    measurement = row["measurement"]
    assert measurement["after_repetitions"] == 1
    assert measurement["baseline_repetitions"] == 1
    assert measurement["statistical_summary"] is False
    assert measurement["preregistered_speedup_target"] == "NONE"


def test_p2_29b_protocol_prevents_remeasurement_and_detection() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_canonical_execution"] is True
    assert protocol["duplicate_after_execution_allowed"] is False
    assert protocol["first_completed_or_failed_after_execution_is_canonical"] is True
    assert protocol["replace_after_result_for_better_numbers"] is False
    assert protocol["baseline_rerun_allowed"] is False
    assert protocol["baseline_result_replacement_allowed"] is False
    assert protocol["detection_must_not_execute"] is True
    assert row["measurement"]["detection_stage_executed"] is False


def test_p2_29b_claim_boundary_is_descriptive_not_generalized() -> None:
    claim = _load()["claim_boundary"]
    assert claim["before_after_comparison"] == "NOT_YET_MEASURED"
    assert claim["comparison_class"] == "PAIRED_SINGLE_OBSERVATION_SAME_MACHINE_CORPUS"
    assert claim["general_speedup"] == "NOT_CLAIMED"
    assert claim["production_capacity"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
    assert claim["detection_accuracy"] == "NOT_EVALUATED"
