import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "performance" / "p2_19_peak_memory_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_19_830dc03"


def load_evidence():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_19_artifact_hashes_are_bound():
    artifacts = load_evidence()["canonical_artifacts"]
    for key, item in artifacts.items():
        path = ROOT / item["path"]
        assert path.is_file(), key
        assert sha256(path) == item["sha256"], key


def test_p2_19_summary_is_completed_at_all_scales():
    data = json.loads((RESULT_DIR / "summary.json").read_text(encoding="utf-8"))
    assert data["status"] == "completed"
    assert data["measurement_order"] == [10000, 100000, 1000000]
    assert [row["scale_events"] for row in data["results"]] == [10000, 100000, 1000000]


def test_p2_19_peak_memory_is_exact_and_nonzero():
    rows = {row["scale_events"]: row for row in load_evidence()["results"]}
    assert rows[10000]["peak_working_set_bytes"] == 219848704
    assert rows[100000]["peak_working_set_bytes"] == 1814085632
    assert rows[1000000]["peak_working_set_bytes"] == 11203510272
    assert rows[1000000]["peak_working_set_mb"] == 10684.5


def test_p2_19_one_million_runtime_and_output_size_are_preserved():
    row = {row["scale_events"]: row for row in load_evidence()["results"]}[1000000]
    assert row["total_seconds"] == 1911.779782
    assert row["throughput_events_per_second"] == 523.073
    assert row["html_bytes"] == 1173795863
    assert row["package_zip_bytes"] == 103543105


def test_p2_19_protocol_does_not_rewrite_p2_18_or_p2_14e():
    protocol = load_evidence()["protocol"]
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["first_completed_or_failed_execution_retained_as_canonical"] is True
    assert protocol["result_replaced_for_better_numbers"] is False
    assert protocol["p2_18_canonical_result_modified"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
    assert protocol["p2_14e_artifacts_modified"] is False


def test_p2_19_claim_boundary_stays_narrow():
    claims = load_evidence()["claim_boundary"]
    assert claims["synthetic_workload"] is True
    assert claims["real_evtx_ingest_performance"] == "NOT_MEASURED"
    assert claims["production_capacity"] == "NOT_CLAIMED"
    assert claims["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claims["statistical_benchmark"] is False
    assert claims["cross_tool_speed_comparison"] == "NOT_CLAIMED"
