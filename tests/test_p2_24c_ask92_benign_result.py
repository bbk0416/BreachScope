from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_24c_136f9f3"
MEASUREMENT = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_24C_ONE_PASS.lock"
RECORD = RESULT_DIR / "result.yaml"
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stored_text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_p2_24c_canonical_measurement_and_lock_are_sealed() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    measurement = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    lock = json.loads(LOCK.read_text(encoding="utf-8"))

    assert record["artifacts"]["measurement"]["original_sha256"] == (
        "cc3435fddb70eb14634f181fb8810a84afd1b429248e774b71f44341db3115f1"
    )
    assert record["artifacts"]["measurement"]["storage_normalization"] == "CRLF_TO_LF_ONLY"
    assert record["artifacts"]["measurement"]["stored_sha256"] == _stored_text_sha256(MEASUREMENT)
    assert _stored_text_sha256(MEASUREMENT) == (
        "c99708cb5b3d684f221840fc728dd80cfe58ed2f7ed616f459e6998ca3f72431"
    )
    assert record["artifacts"]["permanent_lock"]["original_sha256"] == (
        "dab9b8dcedd4be98bb6e4788d38ea755dbd1e469ef7ce95461f93595371dccb6"
    )
    assert record["artifacts"]["permanent_lock"]["stored_sha256"] == _sha256(LOCK)
    assert _sha256(LOCK) == "dab9b8dcedd4be98bb6e4788d38ea755dbd1e469ef7ce95461f93595371dccb6"
    assert lock["analysis_id"] == "p2-24c-ask92-sysmon-20251113-benign-one-pass-v1"

    assert measurement["status"] == "completed"
    assert measurement["contract_sha256"] == "d865b523e08771655f3372c7cca1aca92e0ee389ce6f2794ceb0d91ef624482b"
    assert measurement["runner_sha256"] == "9c4613bca5306928a7b80a6c172c5494b12a9f27b102f4ebe30f60373cf30437"


def test_p2_24c_label_eligibility_passed_on_all_34534_records() -> None:
    measurement = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    gate = measurement["label_eligibility"]
    assert gate["raw_record_count"] == 34_534
    assert gate["parsed_events"] == 34_534
    assert gate["product_parse_errors"] == 0
    assert gate["missing_timestamps"] == 0
    assert gate["timestamp_parse_errors"] == 0
    assert gate["events_after_strict_cutoff"] == 0
    assert gate["min_timestamp_naive"] == "2025-11-08T14:29:00.706320"
    assert gate["max_timestamp_naive"] == "2025-11-13T18:56:23.416739"
    assert gate["strict_cutoff_naive"] == "2025-11-15T23:59:59"
    assert gate["eligible"] is True


def test_p2_24c_measured_2404_flagged_events_on_68_rules() -> None:
    measurement = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    assert measurement["frozen_product"]["repo_commit"] == "dcd7f5bef9ae4e7be8e4d1a55d3a1fc3f3102766"
    assert measurement["frozen_product"]["rules_tree_sha256"] == (
        "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
    )
    assert measurement["frozen_product"]["rule_count"] == 68

    result = measurement["measurement"]
    assert result["status"] == "MEASURED"
    assert result["parsed_benign_events"] == 34_534
    assert result["flagged_benign_events"] == 2_404
    assert result["findings"] == 2_404
    assert result["false_positive_rate"] == 0.06961255574216714
    assert result["false_positive_percent"] == 6.961255574216714
    assert result["rules_evaluated"] == 68
    assert result["findings_by_rule"] == {
        "R-DISCOVERY-Account-System": 56,
        "R-LSASS-Dump": 1,
        "R-PROCESS-Discovery": 498,
        "R-PS-Bypass": 1838,
        "R-SCREENSHOT-Capture": 11,
    }
    assert result["findings_by_primary_technique"] == {
        "T1003.001": 1,
        "T1057": 498,
        "T1059.001": 1838,
        "T1087.001": 56,
        "T1113": 11,
    }


def test_p2_24c_result_preserves_one_pass_and_claim_boundaries() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    execution = record["execution"]
    boundary = record["evidence_boundary"]

    assert execution["one_pass"] is True
    assert execution["permanent_lock_acquired"] is True
    assert execution["rerun_allowed"] is False
    assert execution["first_completed_or_failed_execution_is_canonical"] is True
    assert execution["contract_merged_before_record_parse"] is True
    assert execution["contract_merge_commit"] == "136f9f38d5f52f6a32a32e41788a7f3cca1ae738"
    assert execution["result_replaced_for_better_numbers"] is False
    assert execution["product_or_rules_tuned_from_result"] is False

    assert boundary["fresh_single_source_full_rulepack_measurement"] is True
    assert boundary["source_intent_benign_label"] is True
    assert boundary["event_level_manual_adjudication"] is False
    assert boundary["flagged_events_are_confirmed_false_positives"] is False
    assert boundary["confirmed_false_positives"] == "NOT_CLAIMED"
    assert boundary["general_fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["representative_production_population"] == "NOT_CLAIMED"


def test_current_evidence_index_adds_p2_24c_without_widening_global_claims() -> None:
    current = yaml.safe_load(CURRENT.read_text(encoding="utf-8"))
    rows = {row["evidence_id"]: row for row in current["benign_operational_evidence"]}
    p24c = rows["p2-24c-ask92-sysmon-benign-one-pass"]

    assert p24c["class"] == "independent_source_intent_benign_sysmon_one_pass"
    assert p24c["status"] == "COMPLETED"
    assert p24c["detector_rule_count"] == 68
    assert p24c["raw_records"] == 34_534
    assert p24c["parsed_records"] == 34_534
    assert p24c["parse_errors"] == 0
    assert p24c["missing_timestamps"] == 0
    assert p24c["events_after_strict_cutoff"] == 0
    assert p24c["findings"] == 2_404
    assert p24c["flagged_events"] == 2_404
    assert p24c["observed_source_intent_benign_flagged_event_fraction"] == 0.06961255574216714
    assert p24c["event_level_manual_adjudication"] is False
    assert p24c["confirmed_false_positives"] == "NOT_CLAIMED"
    assert p24c["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert p24c["production_false_positive_rate"] == "NOT_CLAIMED"

    boundary = current["claim_boundary"]
    assert boundary["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert boundary["confirmed_false_positives"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["production_accuracy"] == "NOT_CLAIMED"
