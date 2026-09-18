from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "performance" / "p2_23b_peak_memory_result.yaml"
RESULT_DIR = ROOT / "performance" / "results" / "p2_23b_af5fdbf"


def _load() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_23b_artifact_hashes_are_bound() -> None:
    for key, item in _load()["canonical_artifacts"].items():
        path = ROOT / item["path"]
        assert path.is_file(), key
        assert _sha256(path) == item["sha256"], key


def test_p2_23b_summary_completed_all_preregistered_scales() -> None:
    data = json.loads((RESULT_DIR / "summary.json").read_text(encoding="utf-8"))
    assert data["status"] == "completed"
    assert data["measurement_order"] == [10000, 100000, 1000000]
    assert [row["scale_events"] for row in data["results"]] == [10000, 100000, 1000000]
    assert data["source"]["size_bytes"] == 454_835_896
    assert data["source"]["sha256"] == "e4e85502d926376c9d75745a7f1e81fec6eba38faaa7c5201f03fd2b6e18cc9f"


def test_p2_23b_peak_memory_values_are_exact_and_nonzero() -> None:
    rows = {row["scale_events"]: row for row in _load()["results"]}
    assert rows[10000]["peak_working_set_bytes"] == 112_603_136
    assert rows[100000]["peak_working_set_bytes"] == 605_650_944
    assert rows[1000000]["peak_working_set_bytes"] == 5_501_534_208
    assert rows[1000000]["peak_working_set_mb"] == 5246.672


def test_p2_23b_one_million_runtime_and_outputs_are_preserved() -> None:
    row = {row["scale_events"]: row for row in _load()["results"]}[1000000]
    assert row["total_seconds"] == 1046.566331
    assert row["throughput_events_per_second"] == 955.506
    assert row["findings"] == 1000
    assert row["flagged_events"] == 1000
    assert row["html_bytes"] == 3_762_485
    assert row["package_zip_bytes"] == 49_703_380


def test_p2_23b_protocol_preserves_prior_evidence() -> None:
    row = _load()
    protocol = row["protocol"]
    assert row["relation_to_p2_23"]["p2_23_status"] == "FAILED_PRECONDITION"
    assert row["relation_to_p2_23"]["same_benchmark_id_reused"] is False
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["permanent_lock_sha256"] == "b44b3429e3a0e4896ce9b30799b96574484b6fa4c28d5bb019ece8f4a641c212"
    assert protocol["first_completed_or_failed_execution_retained_as_canonical"] is True
    assert protocol["result_replaced_for_better_numbers"] is False
    assert protocol["p2_23_failed_precondition_preserved"] is True
    assert protocol["p2_19_canonical_result_modified"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False


def test_p2_23b_historical_comparison_is_not_claimed_exact() -> None:
    context = _load()["historical_context"]
    assert context["same_synthetic_input_hash"] is True
    assert context["exact_product_version_match"] is False
    assert context["p2_19_rule_count"] == 66
    assert context["p2_23b_rule_count"] == 68
    assert context["p2_19_one_million_peak_working_set_mb"] == 10684.5
    assert context["p2_23b_one_million_peak_working_set_mb"] == 5246.672
    assert "not claimed as an exact apples-to-apples" in context["comparison_note"]


def test_p2_23b_claim_boundary_stays_narrow() -> None:
    claims = _load()["claim_boundary"]
    assert claims["synthetic_workload"] is True
    assert claims["real_evtx_ingest_performance"] == "NOT_MEASURED"
    assert claims["production_capacity"] == "NOT_CLAIMED"
    assert claims["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claims["statistical_benchmark"] is False
    assert claims["exact_p2_19_apples_to_apples_comparison"] == "NOT_CLAIMED"
    assert claims["cross_tool_speed_comparison"] == "NOT_CLAIMED"
