import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_18_benchmark_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_18_performance_benchmark.py"


def load():
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_runner_is_frozen_before_measurement():
    row = load()
    assert row["status"] == "PREREGISTERED_BEFORE_MEASUREMENT"
    assert hashlib.sha256(RUNNER.read_bytes()).hexdigest() == row["runner"]["sha256"]
    assert row["product"]["repo_commit"] == "6b63cdead6e524d1ee60e9193b5353a2151767cd"
    assert row["product"]["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"


def test_sizes_and_execution_order_are_fixed():
    measurement = load()["measurement"]
    assert measurement["sizes_events"] == [10000, 100000, 1000000]
    assert measurement["order"] == "ascending"
    assert measurement["fresh_python_process_per_size"] is True
    assert measurement["parallel_detection"] is True
    assert measurement["max_workers"] == 8


def test_input_generator_is_deterministic_and_nontrivial():
    source = load()["input_generator"]
    assert source["deterministic"] is True
    assert source["total_events"] == 1000000
    assert source["synthetic_suspicious_interval"] == 1000
    assert source["synthetic_suspicious_fraction"] == 0.001
    assert source["generation_time_included_in_benchmark"] is False


def test_runner_measures_peak_working_set_and_full_core_pipeline():
    source = RUNNER.read_text(encoding="utf-8")
    assert "PeakWorkingSetSize" in source
    assert "pipe.collect_events" in source
    assert "pipe.analyze" in source
    assert "pipe.correlate" in source
    assert "pipe.infer_scenarios" in source
    assert "pipe.build_report" in source
    assert "pipe.export_report" in source
    assert "subprocess.run(cmd" in source


def test_claims_and_failure_policy_are_narrow():
    row = load()
    protocol = row["protocol"]
    claims = row["claim_boundary"]
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["failed_scale_stops_later_scales"] is True
    assert claims["real_evtx_ingest_performance"] == "NOT_MEASURED"
    assert claims["production_capacity"] == "NOT_CLAIMED"
    assert claims["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claims["cross_tool_speed_comparison"] == "NOT_CLAIMED"
