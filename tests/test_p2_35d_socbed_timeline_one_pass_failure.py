from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "p2_35d_socbed_timeline_one_pass_failure.yaml"
FIRST_DIR = ROOT / "external_baseline" / "results" / "p2_35d_38e3c51"
DUP_DIR = ROOT / "external_baseline" / "results" / "p2_35d_bea0012"
FIRST_RAW = FIRST_DIR / "result.json"
FIRST_LOCK = FIRST_DIR / "P2_35D_ONE_PASS.lock"
DUP_RAW = DUP_DIR / "result.json"
DUP_LOCK = DUP_DIR / "P2_35D_ONE_PASS.lock"
CONTRACT = ROOT / "external_baseline" / "p2_35d_socbed_timeline_one_pass_contract.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_35d_first_failed_canonical_artifacts_are_sealed() -> None:
    row = _load()
    assert row["status"] == "FAILED_CANONICAL"
    assert row["contract_main_commit"] == "bea00124dc7f50ff901beda2846b3e48c0d9b6f5"
    assert row["canonical_repo_commit"] == "38e3c51cb68af8783904637078b80c756207b0e3"
    assert FIRST_RAW.stat().st_size == 806
    assert FIRST_LOCK.stat().st_size == 115
    assert _sha256(FIRST_RAW) == "9f31ad800e47c32a66cf5c8ac457602d85063e801eb40db54de05b81e7147581"
    assert _sha256(FIRST_LOCK) == "4d0e9c8e97f1ff21a5b94152391e4ce9059bab4e185963668a67c5d3f243db98"


def test_p2_35d_duplicate_execution_is_preserved_as_protocol_violation() -> None:
    row = _load()
    duplicate = row["canonical_artifacts"]["duplicate_execution"]
    assert DUP_RAW.stat().st_size == 806
    assert DUP_LOCK.stat().st_size == 113
    assert _sha256(DUP_RAW) == "9f31ad800e47c32a66cf5c8ac457602d85063e801eb40db54de05b81e7147581"
    assert _sha256(DUP_LOCK) == "383b3b59c77842f5c5a1cb1809cca686fc7c1f268c184985d49c47ffeab224ca"
    assert _sha256(DUP_RAW) == _sha256(FIRST_RAW)
    assert _sha256(DUP_LOCK) != _sha256(FIRST_LOCK)
    assert duplicate["canonical_status"] == "NONCANONICAL_PROTOCOL_VIOLATION"
    assert duplicate["result"]["identical_to_first_result"] is True
    assert duplicate["same_exception_as_first"] is True


def test_p2_35d_raw_failure_is_runner_import_bootstrap_only() -> None:
    raw = json.loads(FIRST_RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "failed"
    assert raw["runner_sha256"] == "892babc03a073a151bdede33561740595dd1cf0821c2e838eb762b4ea6979a72"
    assert raw["source"]["archive_sha256"] == "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    assert raw["product"]["breachscope_and_rules_match_frozen_commit"] is True
    assert raw["exception"] == "ModuleNotFoundError: No module named 'breachscope'"
    failure = _load()["failure"]
    assert failure["stage"] == "TIMING_ANCHOR_TIMESTAMP_PARSE_IMPORT"
    assert failure["quoted_timing_parser_matched_record"] is True
    assert failure["selected_jsonl_decoded"] is False
    assert failure["breachscope_detection_executed"] is False
    assert failure["breachscope_correlation_executed"] is False
    assert failure["breachscope_scenario_inference_executed"] is False


def test_p2_35d_posthoc_diagnosis_preserves_product_claim_boundary() -> None:
    row = _load()
    diagnosis = row["posthoc_diagnosis"]
    assert diagnosis["cause"] == "EVALUATOR_RUNNER_REPO_IMPORT_BOOTSTRAP_MISSING"
    assert diagnosis["runner_repo_root_sys_path_bootstrap_present"] is False
    assert diagnosis["p2_35c_quoted_structured_log_parser_problem_resolved"] is True
    assert diagnosis["product_or_rule_failure"] is False
    assert diagnosis["source_archive_identity_failure"] is False
    assert diagnosis["selected_windows_jsonl_failure"] is False

    source = row["source"]
    assert source["selected_windows_member"]["decoded_as_text_before_failure"] is False
    assert source["selected_windows_member"]["json_rows_parsed_before_failure"] is False
    assert source["timing_anchor_member"]["quoted_run_attack_record_matched_before_failure"] is True
    assert source["timing_anchor_member"]["timestamp_parsed_before_failure"] is False


def test_p2_35d_protocol_records_duplicate_and_forbids_retry() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["first_completed_or_failed_execution_retained_as_canonical"] is True
    assert protocol["duplicate_p2_35d_canonical_execution_performed"] is True
    assert protocol["duplicate_execution_count"] == 1
    assert protocol["protocol_violation_detected"] is True
    assert protocol["first_execution_remains_canonical"] is True
    assert protocol["second_execution_result_must_not_replace_first"] is True
    assert protocol["result_replaced_for_better_outcome"] is False
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert row["next_step"]["id"] == "P2-35E"
    assert "analysis-id-global exclusive lock" in row["next_step"]["requirement"]
    assert row["next_step"]["p2_35d_must_remain_immutable"] is True


def test_p2_35d_claims_remain_unmeasured() -> None:
    claim = _load()["claim_boundary"]
    assert claim["source_attack_invocation_order"] == "NOT_MEASURED_BY_P2_35D_CANONICAL"
    assert claim["temporal_window_occupancy"] == "NOT_MEASURED"
    assert claim["attack_step_semantic_attribution"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["chain_recall"] == "NOT_EVALUATED"
    assert claim["scenario_recall"] == "NOT_EVALUATED"
    assert claim["production_reconstruction_quality"] == "NOT_CLAIMED"


def test_p2_35d_locks_are_byte_exact_and_contract_id_is_unchanged() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert "external_baseline/results/p2_35d_38e3c51/P2_35D_ONE_PASS.lock -text -whitespace" in attrs
    assert "external_baseline/results/p2_35d_bea0012/P2_35D_ONE_PASS.lock -text -whitespace" in attrs
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    assert contract["analysis_id"] == "p2-35d-socbed-acsac2021-timeline-one-pass-v1"
