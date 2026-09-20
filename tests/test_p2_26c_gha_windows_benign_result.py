from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_26c_81b839d"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_26C_ONE_PASS.lock"
RECORD = RESULT_DIR / "result.yaml"
CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_26c_canonical_artifacts_are_sealed() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    assert record["status"] == "COMPLETED"
    assert record["artifacts"]["measurement"]["original_sha256"] == (
        "839d9bb5083fa433ddc29ffdce33252767ce805e5c654cf6ad94fa5d85ed7658"
    )
    assert record["artifacts"]["measurement"]["stored_sha256"] == _sha256(RAW)
    assert _sha256(RAW) == "9cff2b8616632031807dffa4771eb69e37f1040ef28576b9bd73442bbeb3264c"
    assert record["artifacts"]["permanent_lock"]["original_sha256"] == (
        "cde7cb5ca7d6e5225592a9354694daa59d6deb536d825f3c662a62427b732906"
    )
    assert _sha256(LOCK) == "cde7cb5ca7d6e5225592a9354694daa59d6deb536d825f3c662a62427b732906"


def test_p2_26c_first_run_result_is_one_of_1643_with_zero_parse_errors() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["python"].startswith("3.11.9 ")
    assert raw["frozen_product"]["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert raw["frozen_product"]["rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert raw["frozen_product"]["rule_count"] == 68
    assert raw["parse_summary"] == {
        "raw_records": 1643,
        "parsed_events": 1643,
        "parse_errors": 0,
    }
    measurement = raw["measurement"]
    assert measurement["status"] == "MEASURED"
    assert measurement["parsed_events"] == 1643
    assert measurement["parse_errors"] == 0
    assert measurement["flagged_events"] == 1
    assert measurement["findings"] == 1
    assert measurement["observed_source_intent_benign_flagged_event_fraction"] == 0.0006086427267194157
    assert measurement["observed_source_intent_benign_flagged_event_percent"] == 0.06086427267194157
    assert measurement["findings_by_rule"] == {"R-SCHTASK-4698": 1}
    assert measurement["findings_by_channel"] == {"Security": 1}
    assert measurement["flagged_events_by_channel"] == {"Security": 1}


def test_p2_26c_all_bound_channel_counts_are_preserved() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    observed = {
        row["channel"]: (row["raw_records"], row["parsed_events"], row["parse_errors"])
        for row in raw["channels"]
    }
    assert observed == {
        "Security": (1212, 1212, 0),
        "System": (347, 347, 0),
        "Application": (84, 84, 0),
        "Windows PowerShell": (0, 0, 0),
        "Microsoft-Windows-PowerShell/Operational": (0, 0, 0),
    }


def test_p2_26c_claim_boundary_does_not_turn_flag_into_confirmed_fp_or_production_fpr() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    boundary = record["evidence_boundary"]
    assert boundary["fresh_benign_revalidation_completed"] is True
    assert boundary["event_level_manual_adjudication"] is False
    assert boundary["flagged_events_are_confirmed_false_positives"] is False
    assert boundary["confirmed_false_positives"] == "NOT_CLAIMED"
    assert boundary["general_fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["representative_production_population"] == "NOT_CLAIMED"


def test_current_chain_marks_p2_26c_fresh_benign_revalidation_complete() -> None:
    chain = yaml.safe_load(CHAIN.read_text(encoding="utf-8"))
    assert chain["current_evidence_id"] == "p2-26c-fresh-benign-revalidation-current-detection-evidence"
    row = chain["post_remediation_revalidations"][1]
    assert row["revalidation_id"] == "p2-26c-gha-windows-fresh-benign"
    assert row["fresh_benign_revalidation"] == "COMPLETED"
    assert row["parsed_events"] == 1643
    assert row["flagged_events"] == 1
    assert row["flagged_events_are_confirmed_false_positives"] is False
    assert chain["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
