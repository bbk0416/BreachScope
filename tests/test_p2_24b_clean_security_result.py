from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_24b_e726531"
MEASUREMENT = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_24B_ONE_PASS.lock"
RECORD = RESULT_DIR / "result.yaml"
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stored_text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_p2_24b_canonical_measurement_and_lock_are_sealed_exactly() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    measurement = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    lock = json.loads(LOCK.read_text(encoding="utf-8"))

    assert record["artifacts"]["measurement"]["original_sha256"] == (
        "fc2a91890d05584b2b59dcd9c3ab452fb58e6d9cb9d9d8b97913aac5c0f753a7"
    )
    assert record["artifacts"]["measurement"]["storage_normalization"] == "CRLF_TO_LF_ONLY"
    assert record["artifacts"]["measurement"]["stored_sha256"] == _stored_text_sha256(MEASUREMENT)
    assert _stored_text_sha256(MEASUREMENT) == (
        "6b4dd36e0296efaabbec384e4761dddf17ecfb335253d82be69c8eb7b0a54900"
    )

    assert record["artifacts"]["permanent_lock"]["original_sha256"] == (
        "9787c3373e5e6f396629dfa46befbd725bd644d27cb56819985f9edb5d5d1c36"
    )
    assert record["artifacts"]["permanent_lock"]["stored_sha256"] == _sha256(LOCK)
    assert _sha256(LOCK) == "9787c3373e5e6f396629dfa46befbd725bd644d27cb56819985f9edb5d5d1c36"
    assert lock["analysis_id"] == "p2-24b-queryfarm-clean-security-one-pass-v1"

    assert measurement["status"] == "completed"
    assert measurement["contract_sha256"] == "8653f3395da2a8c24539754b032bea1938a63dfc308d8fe167e29c395db918c4"
    assert measurement["runner_sha256"] == "bafec03a6a65139d9de279091925899b0c26c80373cd8acdd3ae3bf0d49e7510"


def test_p2_24b_measured_zero_of_seven_flagged_on_all_68_rules() -> None:
    measurement = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    assert measurement["frozen_product"]["repo_commit"] == "4a5b16d33781638570f7cee1b6fea56bbd01731c"
    assert measurement["frozen_product"]["rules_tree_sha256"] == (
        "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
    )
    assert measurement["frozen_product"]["rule_count"] == 68
    assert measurement["parse"]["parsed_events"] == 7
    assert measurement["parse"]["parse_errors"] == 0

    result = measurement["measurement"]
    assert result["status"] == "MEASURED"
    assert result["parsed_benign_events"] == 7
    assert result["flagged_benign_events"] == 0
    assert result["findings"] == 0
    assert result["false_positive_rate"] == 0.0
    assert result["false_positive_percent"] == 0.0
    assert result["rules_evaluated"] == 68
    assert result["findings_by_rule"] == {}
    assert result["findings_by_primary_technique"] == {}


def test_p2_24b_result_preserves_one_pass_and_claim_boundaries() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    execution = record["execution"]
    boundary = record["evidence_boundary"]

    assert execution["one_pass"] is True
    assert execution["permanent_lock_acquired"] is True
    assert execution["rerun_allowed"] is False
    assert execution["first_completed_or_failed_execution_is_canonical"] is True
    assert execution["contract_merged_before_record_parse"] is True
    assert execution["contract_merge_commit"] == "e726531e667e1782cf93eb08bf8f1663b20cc765"
    assert execution["result_replaced_for_better_numbers"] is False
    assert execution["product_or_rules_tuned_from_result"] is False

    assert boundary["fresh_full_rulepack_negative_control_measured"] is True
    assert boundary["corpus_representativeness"] == "VERY_LIMITED_7_RECORD_FIXTURE"
    assert boundary["event_level_manual_adjudication"] is False
    assert boundary["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["production_accuracy"] == "NOT_CLAIMED"
    assert boundary["representative_production_population"] == "NOT_CLAIMED"


def test_current_evidence_index_adds_p2_24b_without_widening_global_claims() -> None:
    current = yaml.safe_load(CURRENT.read_text(encoding="utf-8"))
    rows = {row["evidence_id"]: row for row in current["benign_operational_evidence"]}
    p24 = rows["p2-24b-queryfarm-clean-security-one-pass"]

    assert p24["class"] == "independent_source_designated_clean_negative_control"
    assert p24["status"] == "COMPLETED"
    assert p24["detector_rule_count"] == 68
    assert p24["source_documented_records"] == 7
    assert p24["parsed_records"] == 7
    assert p24["parse_errors"] == 0
    assert p24["findings"] == 0
    assert p24["flagged_events"] == 0
    assert p24["observed_fixture_false_positive_rate"] == 0.0
    assert p24["corpus_representativeness"] == "VERY_LIMITED_7_RECORD_FIXTURE"
    assert p24["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert p24["production_false_positive_rate"] == "NOT_CLAIMED"

    boundary = current["claim_boundary"]
    assert boundary["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["production_accuracy"] == "NOT_CLAIMED"
