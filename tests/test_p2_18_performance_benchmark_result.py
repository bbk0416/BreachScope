import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "performance" / "p2_18_benchmark_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_18_5199ff3"


def load_evidence():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_18_artifact_hashes_are_bound():
    row = load_evidence()["canonical_artifacts"]
    for key, item in row.items():
        path = ROOT / item["path"]
        assert path.is_file(), key
        assert sha256(path) == item["sha256"], key


def test_p2_18_summary_keeps_exact_three_scales():
    data = json.loads((RESULT_DIR / "summary.json").read_text(encoding="utf-8"))
    assert data["status"] == "completed"
    assert data["measurement_order"] == [10000, 100000, 1000000]
    assert [r["scale_events"] for r in data["results"]] == [10000, 100000, 1000000]
    assert [r["counts"]["findings"] for r in data["results"]] == [10, 100, 1000]
    assert [r["counts"]["flagged_events"] for r in data["results"]] == [10, 100, 1000]


def test_p2_18_exact_runtime_and_output_size_are_preserved():
    rows = {r["scale_events"]: r for r in load_evidence()["results"]}
    assert rows[10000]["total_seconds"] == 20.501819
    assert rows[100000]["total_seconds"] == 187.255617
    assert rows[1000000]["total_seconds"] == 1902.064694
    assert rows[1000000]["throughput_events_per_second"] == 525.744
    assert rows[1000000]["html_bytes"] == 1173795863
    assert rows[1000000]["package_zip_bytes"] == 103543116


def test_p2_18_missing_peak_memory_is_not_hidden():
    row = load_evidence()
    assert row["status"] == "COMPLETED_WITH_MISSING_PEAK_MEMORY_METRIC"
    for result in row["results"]:
        assert result["peak_working_set_bytes"] is None
        assert result["peak_working_set_mb"] is None
    assert row["claim_boundary"]["peak_memory"] == "NOT_MEASURED"


def test_p2_18_post_completion_duplicate_is_excluded():
    protocol = load_evidence()["protocol"]
    assert protocol["canonical_execution_completed_before_posthoc_duplicate"] is True
    assert protocol["post_completion_duplicate_execution_attempted"] is True
    assert protocol["post_completion_duplicate_terminated"] is True
    assert protocol["post_completion_duplicate_result_accepted"] is False
    assert protocol["canonical_result_artifacts_modified_by_duplicate"] is False
    assert protocol["canonical_local_source_file_later_truncated_by_duplicate"] is True


def test_p2_18_claim_boundary_stays_narrow():
    claims = load_evidence()["claim_boundary"]
    assert claims["synthetic_workload"] is True
    assert claims["real_evtx_ingest_performance"] == "NOT_MEASURED"
    assert claims["production_capacity"] == "NOT_CLAIMED"
    assert claims["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claims["statistical_benchmark"] is False
    assert claims["cross_tool_speed_comparison"] == "NOT_CLAIMED"
