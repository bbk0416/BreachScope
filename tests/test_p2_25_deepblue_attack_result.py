from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_25_e712fc7"
RAW = RESULT_DIR / "result.json"
LOCK = RESULT_DIR / "P2_25_ONE_PASS.lock"
RECORD = RESULT_DIR / "result.yaml"
CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_25_canonical_artifacts_are_sealed() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    assert record["status"] == "COMPLETED"
    assert record["artifacts"]["measurement"]["original_sha256"] == (
        "9ef5da2a55552a735c80d1f4b00c583b2de5fe9f55db687e45ac5532a503f62e"
    )
    assert record["artifacts"]["measurement"]["stored_sha256"] == _sha256(RAW)
    assert _sha256(RAW) == "be56514a196551904f32cd2bd829912cd13ae3bd4a2ce4cc28f268dceca9f664"
    assert record["artifacts"]["permanent_lock"]["original_sha256"] == (
        "a8754be1828436b6525215afa52baa9888ef0ee7784ce4eb0f7bf01509b575d6"
    )
    assert _sha256(LOCK) == "a8754be1828436b6525215afa52baa9888ef0ee7784ce4eb0f7bf01509b575d6"


def test_p2_25_first_run_result_is_6_of_8_with_zero_errors() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["frozen_product"]["rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert raw["frozen_product"]["rule_count"] == 68
    assert raw["summary"] == {
        "fixture_count": 8,
        "hits": 6,
        "misses": 2,
        "errors": 0,
        "fixture_hit_rate": 0.75,
        "wall_seconds": raw["summary"]["wall_seconds"],
    }
    assert sum(row["parsed_events"] for row in raw["datasets"]) == 450
    assert sum(row["parse_errors"] for row in raw["datasets"]) == 0


def test_p2_25_fixture_statuses_are_preserved() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    statuses = {row["dataset_id"]: row["fixture_status"] for row in raw["datasets"]}
    assert statuses == {
        "obfuscation-encoding": "MISS",
        "metasploit-psexec-powershell-security": "HIT",
        "mimikatz-lsadump-sam": "HIT",
        "password-spray": "HIT",
        "powersploit-security": "HIT",
        "psattack-security": "HIT",
        "new-user-security": "MISS",
        "eventlog-manipulation": "HIT",
    }


def test_p2_25_claim_boundary_does_not_turn_fixture_hits_into_recall() -> None:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    boundary = record["evidence_boundary"]
    assert boundary["fresh_attack_revalidation_completed"] is True
    assert boundary["fixture_hit_rate_is_event_level_recall"] is False
    assert boundary["event_level_ground_truth"] == "NOT_AVAILABLE"
    assert boundary["event_level_recall"] == "NOT_CLAIMED"
    assert boundary["technique_recall"] == "NOT_CLAIMED"
    assert boundary["production_recall"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"


def test_current_chain_keeps_attack_revalidation_and_adds_fresh_benign() -> None:
    chain = yaml.safe_load(CHAIN.read_text(encoding="utf-8"))
    assert chain["current_evidence_id"] == "independent-command-coverage-remediation-current-detection-evidence"

    assert chain["current_rulepack_validation"]["prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack"] is False
    assert chain["current_rulepack_validation"]["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"

    attack = chain["post_remediation_revalidations"][0]
    assert attack["detector_rules_tree_sha256"] != chain["current_frozen_detector"]["rules_tree_sha256"]
    assert attack["fresh_attack_revalidation"] == "COMPLETED"
    assert attack["fixture_count"] == 8
    assert attack["hits"] == 6
    assert attack["misses"] == 2
    assert attack["fixture_hit_rate"] == 0.75

    benign = chain["post_remediation_revalidations"][1]
    assert benign["fresh_benign_revalidation"] == "COMPLETED"
    assert benign["parsed_events"] == 1643
    assert benign["parse_errors"] == 0
    assert benign["findings"] == 1
    assert benign["flagged_events"] == 1
    assert benign["observed_source_intent_benign_flagged_event_fraction"] == 0.0006086427267194157
    assert benign["flagged_events_are_confirmed_false_positives"] is False

    # P2-24D remains a historical at-the-time remediation record.
    assert chain["posthoc_remediations"][0]["fresh_benign_revalidation"] == "NOT_RUN"
    assert chain["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
