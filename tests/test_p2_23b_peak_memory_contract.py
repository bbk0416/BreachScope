from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_23b_peak_memory_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_23b_peak_memory_benchmark.py"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _stored_text_sha256(path: Path) -> str:
    data = path.read_bytes().replace(bytes([13, 10]), bytes([10]))
    return hashlib.sha256(data).hexdigest()


def test_p2_23b_uses_new_id_without_product_change() -> None:
    row = _load()
    assert row["benchmark_id"] == "p2-23b-windows-bounded-html-peak-memory-10k-100k-1m-v1"
    assert row["status"] == "PREREGISTERED_AFTER_P2_23_PRECONDITION_FAILURE"
    assert row["relation_to_p2_23"]["prior_status"] == "FAILED_PRECONDITION"
    assert row["relation_to_p2_23"]["prior_measurement_rows"] == 0
    assert row["relation_to_p2_23"]["same_benchmark_id_reused"] is False
    assert row["relation_to_p2_23"]["product_or_rules_changed_after_prior_failure"] is False
    assert row["product"]["repo_commit"] == "62c5cf38bd566c4ec37ec52f55a68ca63ced8758"
    assert row["product"]["rule_count"] == 68


def test_p2_23b_binds_runner_and_exact_python_launcher() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _stored_text_sha256(RUNNER)
    assert row["runner"]["python_major_minor"] == "3.11"
    invocation = row["canonical_invocation"]
    assert invocation["launcher"] == "py -3.11"
    assert invocation["observed_launcher_version_before_registration"] == "3.11.9"
    assert invocation["dependency_preflight"] == {
        "yaml_import": "PASS",
        "jinja2_import": "PASS",
    }
    assert invocation["default_python_launcher_prohibited"] is True


def test_p2_23b_reuses_exact_synthetic_input() -> None:
    source = _load()["input"]
    assert source["expected_events"] == 1_000_000
    assert source["expected_size_bytes"] == 454_835_896
    assert source["expected_sha256"] == "e4e85502d926376c9d75745a7f1e81fec6eba38faaa7c5201f03fd2b6e18cc9f"


def test_p2_23b_is_one_pass_fail_closed() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_must_merge_before_canonical_execution"] is True
    assert protocol["exact_launcher_must_match_canonical_invocation"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["source_hash_or_size_mismatch_fails_closed"] is True
    assert protocol["missing_or_zero_peak_memory_fails_worker"] is True


def test_p2_23b_claim_boundary_stays_narrow() -> None:
    claims = _load()["claim_boundary"]
    assert claims["real_evtx_ingest_performance"] == "NOT_MEASURED"
    assert claims["production_capacity"] == "NOT_CLAIMED"
    assert claims["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claims["exact_p2_19_apples_to_apples_comparison"] == "NOT_CLAIMED"
