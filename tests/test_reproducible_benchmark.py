from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_SCRIPT = ROOT / "scripts" / "verify_reproducible_benchmark.py"
CURRENT_SCRIPT = ROOT / "scripts" / "verify_current_detection_evidence.py"
MANIFEST = ROOT / "external_baseline" / "p2_09e_benchmark.yaml"
CURRENT_CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def test_historical_p2_09e_verifier_fails_closed_after_rule_drift() -> None:
    proc = subprocess.run(
        [sys.executable, str(HISTORICAL_SCRIPT), "--json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 1
    assert "current rule tree hash" in proc.stdout
    assert "543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce" in proc.stdout
    assert "8ade507d0abf4a0495b44cde4268245dab8c5f9d58d2eb5b47ebee8b7a5de185" in proc.stdout


def test_current_detection_evidence_chain_verifies_without_network() -> None:
    proc = subprocess.run(
        [sys.executable, str(CURRENT_SCRIPT), "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)

    assert data["status"] == "PASS"
    assert data["base_rules_tree_sha256"] == (
        "543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce"
    )
    assert data["current_rules_tree_sha256"] == (
        "8ade507d0abf4a0495b44cde4268245dab8c5f9d58d2eb5b47ebee8b7a5de185"
    )
    assert data["base_attack_scenario_hits"] == 2
    assert data["current_attack_scenario_hits"] == 3
    assert data["attack_scenario_total"] == 10
    assert data["historical_benign"]["events"] == 766623
    assert data["historical_benign"]["false_positives"] == 17
    assert data["historical_benign"]["true_negatives"] == 766606
    assert data["historical_benign"]["applies_to_rules_tree_sha256"] == data["base_rules_tree_sha256"]
    assert len(data["remediations"]) == 1
    remediation = data["remediations"][0]
    assert remediation["remediation_id"] == "p2-10a-scheduled-task-4698"
    assert remediation["attack_scenario_hits_before"] == 2
    assert remediation["attack_scenario_hits_after"] == 3
    assert remediation["benign_non_sysmon_events_scanned"] == 34423
    assert remediation["benign_exact_predicate_matches"] == 0
    assert remediation["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"


def test_benchmark_claim_boundaries_are_explicit() -> None:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    assert data["benchmark_type"] == "detection_evidence_not_performance"
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["performance_benchmark"] == "NOT_CLAIMED"
    assert data["reproducibility"]["network_required_for_recorded_evidence_verification"] is False


def test_benchmark_keeps_historical_attack_and_benign_rule_hash_equal() -> None:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    common = data["common_detection_contract"]["rules_tree_sha256"]
    components = data["components"]

    assert components["attack_external_baseline"]["rules_tree_sha256"] == common
    assert components["benign_external_baseline"]["rules_tree_sha256"] == common
    assert data["common_detection_contract"]["commit_range_detection_semantics_changed"] is False


def test_current_chain_keeps_claim_boundaries_explicit() -> None:
    data = yaml.safe_load(CURRENT_CHAIN.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.current_detection_evidence_chain.v1"
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
