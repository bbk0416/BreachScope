from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_23_peak_memory_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_23_peak_memory_benchmark.py"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_23_contract_binds_merged_product_and_runner() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_BEFORE_CANONICAL_1M_MEASUREMENT"
    assert row["product"]["repo_commit"] == "62c5cf38bd566c4ec37ec52f55a68ca63ced8758"
    assert row["product"]["optimization_commit"] == "13b21e077b351dcbcb8900a5053f28b8a0e1ed31"
    assert row["product"]["rules_tree_sha256"] == "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
    assert row["product"]["rule_count"] == 68
    assert row["runner"]["sha256"] == _sha256(RUNNER)


def test_p2_23_reuses_exact_p2_19_synthetic_input_contract() -> None:
    source = _load()["input"]
    assert source["deterministic_generator_same_as_p2_19"] is True
    assert source["expected_events"] == 1_000_000
    assert source["expected_size_bytes"] == 454_835_896
    assert source["expected_sha256"] == "e4e85502d926376c9d75745a7f1e81fec6eba38faaa7c5201f03fd2b6e18cc9f"


def test_p2_23_discloses_exploratory_100k_observation() -> None:
    disclosure = _load()["pre_registration_disclosure"]
    assert disclosure["exploratory_100k_probe_observed_before_this_contract"] is True
    assert disclosure["exploratory_probe_was_canonical"] is False
    assert disclosure["exploratory_100k_peak_mib"] == {
        "control": 1606.504,
        "candidate": 494.051,
    }


def test_p2_23_canonical_protocol_is_fail_closed_and_one_pass() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_committed_before_canonical_1m_measurement"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["product_or_rules_tuning_after_contract_before_canonical_result"] is False
    assert protocol["source_hash_or_size_mismatch_fails_closed"] is True
    assert protocol["missing_or_zero_peak_memory_fails_worker"] is True


def test_p2_23_claim_boundary_stays_narrow() -> None:
    claims = _load()["claim_boundary"]
    assert claims["formal_100k_result_is_fresh"] is False
    assert claims["formal_1m_result_is_first_post_contract_1m_observation"] is True
    assert claims["production_capacity"] == "NOT_CLAIMED"
    assert claims["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claims["exact_p2_19_apples_to_apples_comparison"] == "NOT_CLAIMED"
