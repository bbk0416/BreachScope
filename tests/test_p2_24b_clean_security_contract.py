from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_24b_clean_security_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_24b_clean_security_one_pass.py"

SOURCE_SHA256 = "50c87926d2dfed9776906ffbcc77e61577940910a71fb1c1871860a4e2213456"
SOURCE_BLOB = "7c0eab77b0ed388da193827a14286a56634b3a6b"
RULE_HASH = "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_p2_24b_binds_exact_source_bytes_and_frozen_rulepack() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_BEFORE_EVTX_CONTENT_OBSERVATION"
    assert row["frozen_product"]["repo_commit"] == "4a5b16d33781638570f7cee1b6fea56bbd01731c"
    assert row["frozen_product"]["rules_tree_sha256"] == RULE_HASH
    assert row["frozen_product"]["rule_count"] == 68
    source = row["source"]
    assert source["size_bytes"] == 69632
    assert source["git_blob_sha1"] == SOURCE_BLOB
    assert source["sha256"] == SOURCE_SHA256
    assert source["source_documented_record_count"] == 7


def test_p2_24b_runner_is_hash_bound_before_content_observation() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _text_sha256(RUNNER)
    assert row["runner"]["permanent_exclusive_lock"] is True
    observed = row["phase_b_identity_observation"]
    assert observed["binary_parsed"] is False
    assert observed["records_observed"] is False
    assert observed["detector_executed"] is False
    assert observed["computed_sha256"] == SOURCE_SHA256


def test_p2_24b_scoring_is_event_level_source_intent_fpr() -> None:
    scoring = _load()["scoring"]
    assert scoring["expected_parsed_events"] == 7
    assert scoring["required_parse_errors"] == 0
    assert scoring["all_68_rules_evaluated"] is True
    assert scoring["source_wide_clean_label_only"] is True
    assert scoring["event_level_manual_adjudication"] is False
    assert scoring["false_positive_rate_formula"] == "flagged_benign_events / parsed_benign_events"
    assert scoring["parse_contract_mismatch_result"] == "NOT_MEASURED"


def test_p2_24b_protocol_is_one_pass_and_fail_closed() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_must_merge_before_any_evtx_record_parse"] is True
    assert protocol["contract_must_merge_before_detector_execution"] is True
    assert protocol["source_identity_reverified_before_parse"] is True
    assert protocol["permanent_lock_acquired_before_source_verification_and_parse"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["source_hash_or_size_mismatch_fails_closed"] is True
    assert protocol["parsed_event_count_mismatch_fails_closed"] is True
    assert protocol["any_parse_error_fails_closed"] is True


def test_p2_24b_claim_boundary_discloses_tiny_negative_control() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_full_rulepack_negative_control"] == "NOT_YET_MEASURED"
    assert claim["benign_false_positive_rate"] == "NOT_YET_MEASURED"
    assert claim["corpus_representativeness"] == "VERY_LIMITED_7_RECORD_FIXTURE"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["representative_production_population"] == "NOT_CLAIMED"
    assert claim["statistical_confidence_interval"] == "NOT_CLAIMED"

