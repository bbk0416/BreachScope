from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_24c_ask92_benign_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_24c_ask92_benign_one_pass.py"

SOURCE_SHA256 = "7a0ff89ae20b0d1a3a5e904ab73f3cbe7fdc7d8eb0fc74dec8f8c906b7014104"
SOURCE_BLOB = "5b25c2dab0c87219fbce6d9ce3d2730257c650ec"
RULE_HASH = "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_p2_24c_contract_binds_exact_source_and_frozen_rules() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_BEFORE_EVTX_CONTENT_OBSERVATION"
    assert row["frozen_product"]["repo_commit"] == "dcd7f5bef9ae4e7be8e4d1a55d3a1fc3f3102766"
    assert row["frozen_product"]["rules_tree_sha256"] == RULE_HASH
    assert row["frozen_product"]["rule_count"] == 68
    source = row["source"]
    assert source["size_bytes"] == 66_129_920
    assert source["git_blob_sha1"] == SOURCE_BLOB
    assert source["sha256"] == SOURCE_SHA256


def test_p2_24c_runner_is_hash_bound_before_content_observation() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _text_sha256(RUNNER)
    assert row["runner"]["permanent_exclusive_lock"] is True
    observed = row["phase_b_identity_observation"]
    assert observed["binary_parsed"] is False
    assert observed["records_observed"] is False
    assert observed["detector_executed"] is False
    assert observed["computed_sha256"] == SOURCE_SHA256


def test_p2_24c_label_gate_mirrors_upstream_timestamp_interpretation_but_is_stricter() -> None:
    gate = _load()["label_eligibility"]
    assert gate["upstream_boundary_conflict_present"] is True
    assert gate["strict_cutoff_naive"] == "2025-11-15T23:59:59"
    assert gate["strict_cutoff_reason"] == "earlier of the documented benign cutoffs"
    assert gate["timestamp_source"] == "EVTX System/TimeCreated@SystemTime"
    assert gate["timestamp_interpretation"] == (
        "datetime.fromisoformat(SystemTime.replace('Z','+00:00')).replace(tzinfo=None)"
    )
    assert gate["required_product_parse_errors"] == 0
    assert gate["required_missing_timestamps"] == 0
    assert gate["required_timestamp_parse_errors"] == 0
    assert gate["required_events_after_strict_cutoff"] == 0
    assert gate["required_parsed_events_equal_raw_records"] is True
    assert gate["failure_result"] == "NOT_MEASURED"
    assert gate["detector_must_not_run_if_ineligible"] is True


def test_p2_24c_scoring_is_full_rulepack_event_fraction_after_gate() -> None:
    scoring = _load()["scoring"]
    assert scoring["all_68_rules_evaluated"] is True
    assert scoring["false_positive_rate_formula"] == "flagged_benign_events / parsed_benign_events"
    assert scoring["event_level_manual_adjudication"] is False
    assert scoring["single_raw_export_only"] is True
    assert scoring["cross_export_duplicate_inflation_avoided"] is True


def test_p2_24c_protocol_is_one_pass_and_fail_closed() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_must_merge_before_any_evtx_record_parse"] is True
    assert protocol["contract_must_merge_before_detector_execution"] is True
    assert protocol["permanent_lock_acquired_before_source_verification_and_parse"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["source_hash_or_size_mismatch_fails_closed"] is True
    assert protocol["label_eligibility_failure_skips_detector"] is True


def test_p2_24c_claims_remain_narrow_before_measurement() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_full_rulepack_single_source_negative_control"] == "NOT_YET_MEASURED"
    assert claim["source_intent_benign_false_positive_rate"] == "NOT_YET_MEASURED"
    assert claim["event_level_benign_ground_truth"] == "NOT_AVAILABLE"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["representative_production_population"] == "NOT_CLAIMED"
    assert claim["statistical_confidence_interval"] == "NOT_CLAIMED"
