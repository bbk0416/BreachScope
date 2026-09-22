from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "p2_35c_socbed_timeline_one_pass_failure.yaml"
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_35c_fcbd39c"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_35C_ONE_PASS.lock"
CONTRACT = ROOT / "external_baseline" / "p2_35c_socbed_timeline_one_pass_contract.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_35c_failed_canonical_artifacts_are_sealed() -> None:
    row = _load()
    assert row["status"] == "FAILED_CANONICAL"
    assert row["contract_main_commit"] == "fcbd39cc8f46ff8b1c893e24e78e339274111065"
    assert RAW.stat().st_size == 979
    assert LOCK.stat().st_size == 115
    assert _sha256(RAW) == (
        "6ec03490bc5541069e629ad8013ed9044ab40ddb3f214a0ae820bd80d3123cae"
    )
    assert _sha256(LOCK) == (
        "3f6cec46b2803c08998801caa22169b5354c9f8c42ddf9e23c807d136c7e60bd"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert row["canonical_artifacts"]["permanent_lock"]["sha256"] == _sha256(LOCK)


def test_p2_35c_raw_failure_is_timing_parser_only() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "failed"
    assert raw["source"]["archive_sha256"] == (
        "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    )
    assert raw["product"]["breachscope_and_rules_match_frozen_commit"] is True
    assert raw["exception"].startswith(
        "RuntimeError: attackconsole run_attack order mismatch: []"
    )
    failure = _load()["failure"]
    assert failure["stage"] == "TIMING_ANCHOR_PARSE"
    assert failure["breachscope_detection_executed"] is False
    assert failure["breachscope_correlation_executed"] is False
    assert failure["breachscope_scenario_inference_executed"] is False


def test_p2_35c_posthoc_diagnosis_records_quoted_log_values() -> None:
    diagnosis = _load()["posthoc_diagnosis"]
    assert diagnosis["cause"] == (
        "EVALUATOR_TIMING_REGEX_DID_NOT_ACCEPT_QUOTED_STRUCTURED_LOG_VALUES"
    )
    assert diagnosis["observed_source_log_syntax_examples"] == [
        'event="run_attack"',
        'attack="misc_sqlmap"',
    ]
    assert diagnosis["source_attack_order_matches_preregistered_eight_steps"] is True
    assert diagnosis["product_or_rule_failure"] is False
    assert diagnosis["source_archive_identity_failure"] is False


def test_p2_35c_cannot_be_retried_under_same_analysis_id() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["permanent_exclusive_lock_used"] is True
    assert protocol["first_completed_or_failed_execution_retained_as_canonical"] is True
    assert protocol["duplicate_p2_35c_canonical_execution_performed"] is False
    assert protocol["result_replaced_for_better_outcome"] is False
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert row["next_step"]["id"] == "P2-35D"
    assert row["next_step"]["p2_35c_must_remain_immutable"] is True


def test_p2_35c_claims_remain_unmeasured() -> None:
    claim = _load()["claim_boundary"]
    assert claim["temporal_window_occupancy"] == "NOT_MEASURED"
    assert claim["attack_step_semantic_attribution"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["chain_recall"] == "NOT_EVALUATED"
    assert claim["scenario_recall"] == "NOT_EVALUATED"
    assert claim["production_reconstruction_quality"] == "NOT_CLAIMED"


def test_p2_35c_lock_is_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "external_baseline/results/p2_35c_fcbd39c/P2_35C_ONE_PASS.lock -text -whitespace"
        in attrs
    )

    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    assert contract["analysis_id"] == "p2-35c-socbed-acsac2021-timeline-one-pass-v1"
