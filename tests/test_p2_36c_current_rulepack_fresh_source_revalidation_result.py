from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "p2_36c_current_rulepack_fresh_source_revalidation_result.yaml"
RAW = ROOT / "external_baseline" / "results" / "p2_36c_3ce807d" / "result.json"
LOCK = ROOT / "external_baseline" / "locks" / "P2_36C_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
CONTRACT = ROOT / "external_baseline" / "p2_36c_current_rulepack_fresh_source_revalidation_contract.yaml"
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_p2_36c_canonical_artifacts_are_byte_exact() -> None:
    summary = _yaml(SUMMARY)
    assert summary["status"] == "COMPLETED"
    assert RAW.stat().st_size == 63_589
    assert LOCK.stat().st_size == 123
    assert _sha(RAW) == "9d1beda76d8e2da10ddd706c70dc7d98343c9b215fbc6c3e535b799e1357c7a4"
    assert _sha(LOCK) == "c7a671fd30cc7ad0c6f76f635cc1c702d997ef0563fad75e6efc6ff704a97fc4"


def test_p2_36c_raw_result_freezes_current_73_rule_detector() -> None:
    raw = _json(RAW)
    assert raw["status"] == "completed"
    assert raw["analysis_id"] == "p2-36c-current-rulepack-fresh-source-revalidation-v1"
    assert raw["contract_sha256"] == _sha(CONTRACT)
    assert raw["runner_sha256"] == "568db0010108f0b012f72b75b0f629b53f910c19a9a842af4b22d5dc18ffb797"
    assert raw["frozen_product"] == {
        "repo_commit": "a469378c0b26bb25ab005ecf2edd681a0b126713",
        "rules_tree_sha256": "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88",
        "rule_count": 73,
        "rule_file_count": 5,
    }


def test_p2_36c_attack_is_one_hit_one_miss_not_recall() -> None:
    raw = _json(RAW)
    summary = raw["attack_revalidation"]["summary"]
    assert summary == {
        "fixture_count": 2,
        "hits": 1,
        "misses": 1,
        "errors": 0,
        "fixture_hit_fraction": 0.5,
    }
    rows = raw["attack_revalidation"]["datasets"]
    assert [(row["dataset_id"], row["fixture_status"]) for row in rows] == [
        ("lazagne_project", "HIT"),
        ("pth_02", "MISS"),
    ]
    claims = raw["claim_boundary"]
    assert claims["attack_fixture_hit_fraction_is_event_level_recall"] is False
    assert claims["production_recall"] == "NOT_CLAIMED"


def test_p2_36c_benign_result_preserves_source_intent_boundary() -> None:
    raw = _json(RAW)
    summary = raw["benign_revalidation"]["summary"]
    assert summary["evtx_member_count"] == 129
    assert summary["empty_member_count"] == 94
    assert summary["nonempty_member_count"] == 35
    assert summary["parsed_events"] == 112_411
    assert summary["parse_errors"] == 0
    assert summary["findings"] == 1
    assert summary["flagged_events"] == 1
    assert summary["observed_source_intent_benign_flagged_event_fraction"] == 1 / 112_411
    assert summary["observed_source_intent_benign_flagged_event_percent"] == 100 / 112_411
    assert summary["findings_by_rule"] == {"R-WMI-QUERY-GET": 1}
    flagged = [row for row in raw["benign_revalidation"]["members"] if row["flagged_events"]]
    assert len(flagged) == 1
    assert flagged[0]["name"] == "win7-x86/Microsoft-Windows-Sysmon%4Operational.evtx"
    claims = raw["claim_boundary"]
    assert claims["benign_flagged_events_are_confirmed_false_positives"] is False
    assert claims["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36c_current_chain_marks_current_rulepack_revalidated() -> None:
    current = _yaml(CURRENT)
    assert current["current_evidence_id"] == (
        "p2-36c-current-rulepack-fresh-source-revalidation-current-detection-evidence"
    )
    validation = current["current_rulepack_validation"]
    assert validation == {
        "rule_change_id": "independent-command-coverage-remediation-v1",
        "current_revalidation_id": "p2-36c-current-rulepack-fresh-source-revalidation",
        "fresh_attack_revalidation_after_current_rule_change": "COMPLETED",
        "fresh_benign_revalidation_after_current_rule_change": "COMPLETED",
        "prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack": False,
        "prior_p2_35m_revalidation_applies_to_current_rulepack": False,
        "fresh_current_rulepack_performance_available": True,
    }
    row = current["post_remediation_revalidations"][-1]
    assert row["revalidation_id"] == "p2-36c-current-rulepack-fresh-source-revalidation"
    assert row["detector_rules_tree_sha256"] == current["current_frozen_detector"]["rules_tree_sha256"]
    assert row["fixture_hit_rate_is_event_level_recall"] is False
    assert row["flagged_events_are_confirmed_false_positives"] is False
    assert row["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36c_protocol_is_one_shot_and_claims_remain_bounded() -> None:
    summary = _yaml(SUMMARY)
    protocol = summary["protocol"]
    assert protocol["canonical_execution_status"] == "COMPLETED"
    assert protocol["one_canonical_execution_only"] is True
    assert protocol["permanent_analysis_id_global_lock_used"] is True
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert protocol["replace_result_for_better_outcome"] is False

    claims = summary["claim_boundary"]
    assert claims["independent_source_family_holdout"] is False
    assert claims["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert claims["production_accuracy"] == "NOT_CLAIMED"
    assert claims["production_precision"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36c_artifacts_are_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "external_baseline/locks/P2_36C_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock "
        "-text -whitespace"
    ) in attrs
    assert (
        "external_baseline/results/p2_36c_3ce807d/result.json "
        "-text -eol -whitespace"
    ) in attrs
