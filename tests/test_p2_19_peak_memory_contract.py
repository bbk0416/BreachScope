import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_19_peak_memory_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_19_peak_memory_benchmark.py"


def load():
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_19_freezes_runner_product_and_same_source_bytes():
    row = load()
    assert row["status"] == "PREREGISTERED_BEFORE_MEASUREMENT"
    assert row["product"]["repo_commit"] == "6b63cdead6e524d1ee60e9193b5353a2151767cd"
    assert row["product"]["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert row["runner"]["sha256"] == sha256(RUNNER)
    assert row["input"]["expected_sha256"] == "e4e85502d926376c9d75745a7f1e81fec6eba38faaa7c5201f03fd2b6e18cc9f"
    assert row["input"]["expected_size_bytes"] == 454835896


def test_p2_19_is_new_benchmark_not_p2_18_rewrite():
    relation = load()["relation_to_p2_18"]
    assert relation["prior_benchmark_id"] == "p2-18-windows-core-pipeline-10k-100k-1m-v1"
    assert relation["prior_result_status"] == "COMPLETED_WITH_MISSING_PEAK_MEMORY_METRIC"
    assert relation["prior_timing_result_is_replaced"] is False
    assert relation["new_benchmark_id_required"] is True


def test_p2_19_memory_api_binding_is_explicit_and_fail_closed():
    row = load()
    runner = row["runner"]
    assert runner["memory_api"] == "GetProcessMemoryInfo"
    assert runner["memory_metric"] == "PeakWorkingSetSize"
    assert runner["windows_64bit_handle_restype_explicit"] is True
    assert runner["psapi_argtypes_and_restype_explicit"] is True
    source = RUNNER.read_text(encoding="utf-8")
    assert 'kernel32.GetCurrentProcess.restype = wintypes.HANDLE' in source
    assert 'psapi.GetProcessMemoryInfo.argtypes' in source
    assert 'psapi.GetProcessMemoryInfo.restype = wintypes.BOOL' in source
    assert 'raise RuntimeError("peak working set was not captured")' in source


def test_p2_19_sizes_stages_and_lock_are_preregistered():
    row = load()
    measurement = row["measurement"]
    assert measurement["sizes_events"] == [10000, 100000, 1000000]
    assert measurement["fresh_python_process_per_size"] is True
    assert measurement["max_workers"] == 8
    assert measurement["peak_memory_scope"] == "entire worker process lifetime through report export"
    protocol = row["protocol"]
    assert protocol["contract_committed_before_measurement"] is True
    assert protocol["permanent_lock_acquired_before_source_generation"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["missing_or_zero_peak_memory_fails_worker"] is True
    assert protocol["p2_18_canonical_result_modified"] is False


def test_p2_19_instrumentation_preflight_is_not_corpus_measurement():
    pre = load()["instrumentation_preflight"]
    assert pre["corpus_measurement_started"] is False
    assert pre["result"] == "PASS"
    assert pre["observed_peak_working_set_bytes"] > 0


def test_p2_19_claim_boundary_is_narrow():
    claims = load()["claim_boundary"]
    assert claims["synthetic_workload"] is True
    assert claims["real_evtx_ingest_performance"] == "NOT_MEASURED"
    assert claims["production_capacity"] == "NOT_CLAIMED"
    assert claims["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claims["statistical_benchmark"] is False
    assert claims["cross_tool_speed_comparison"] == "NOT_CLAIMED"
