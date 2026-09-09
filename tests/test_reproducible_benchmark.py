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
    assert "c8aab1fc9dfb54e634f4da12c81bbeb1693f3decef747b543a20bff6153a6409" in proc.stdout


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
        "c8aab1fc9dfb54e634f4da12c81bbeb1693f3decef747b543a20bff6153a6409"
    )
    assert data["base_attack_scenario_hits"] == 2
    assert data["current_attack_scenario_hits"] == 9
    assert data["attack_scenario_total"] == 10
    assert data["historical_benign"]["events"] == 766623
    assert data["historical_benign"]["false_positives"] == 17
    assert data["historical_benign"]["true_negatives"] == 766606
    assert data["historical_benign"]["applies_to_rules_tree_sha256"] == data["base_rules_tree_sha256"]
    assert len(data["remediations"]) == 7

    p2_10a = data["remediations"][0]
    assert p2_10a["remediation_id"] == "p2-10a-scheduled-task-4698"
    assert p2_10a["attack_scenario_hits_before"] == 2
    assert p2_10a["attack_scenario_hits_after"] == 3
    assert p2_10a["benign_non_sysmon_events_scanned"] == 34423
    assert p2_10a["benign_exact_predicate_matches"] == 0

    p2_10b = data["remediations"][1]
    assert p2_10b["remediation_id"] == "p2-10b-wmi-xsl"
    assert p2_10b["attack_scenario_hits_before"] == 3
    assert p2_10b["attack_scenario_hits_after"] == 4
    assert p2_10b["benign_sysmon_records_scanned"] == 732200
    assert p2_10b["benign_raw_wmic_records"] == 29
    assert p2_10b["benign_exact_predicate_matches"] == 0
    assert p2_10b["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"

    p2_10c = data["remediations"][2]
    assert p2_10c["remediation_id"] == "p2-10c-domain-admins-4661"
    assert p2_10c["attack_scenario_hits_before"] == 4
    assert p2_10c["attack_scenario_hits_after"] == 5
    assert p2_10c["benign_non_sysmon_events_scanned"] == 34423
    assert p2_10c["benign_security_4661"] == 0
    assert p2_10c["benign_exact_predicate_matches"] == 0
    assert p2_10c["evaluator_control_scenario_hits"] == 4
    assert p2_10c["evaluator_control_findings"] == 5
    assert p2_10c["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"

    p2_10d = data["remediations"][3]
    assert p2_10d["remediation_id"] == "p2-10d-lsass-access-1010"
    assert p2_10d["attack_scenario_hits_before"] == 5
    assert p2_10d["attack_scenario_hits_after"] == 6
    assert p2_10d["benign_sysmon_records_scanned"] == 732200
    assert p2_10d["benign_lsass_event10_target_matches"] == 61
    assert p2_10d["benign_exact_predicate_matches"] == 0
    assert p2_10d["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"

    p2_10e = data["remediations"][4]
    assert p2_10e["remediation_id"] == "p2-10e-winrm-wsmprovhost-child"
    assert p2_10e["attack_scenario_hits_before"] == 6
    assert p2_10e["attack_scenario_hits_after"] == 7
    assert p2_10e["benign_sysmon_records_scanned"] == 732200
    assert p2_10e["benign_sysmon_event1_scanned"] == 2149
    assert p2_10e["benign_exact_predicate_matches"] == 0
    assert p2_10e["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"


    p2_10f = data["remediations"][5]
    assert p2_10f["remediation_id"] == "p2-10f-service-pathless-7045"
    assert p2_10f["attack_scenario_hits_before"] == 7
    assert p2_10f["attack_scenario_hits_after"] == 8
    assert p2_10f["benign_events_scanned"] == 766623
    assert p2_10f["benign_evtx_files_scanned"] == 352
    assert p2_10f["benign_service_control_manager_7045_scanned"] == 26
    assert p2_10f["benign_pathless_imagepath_matches"] == 0
    assert p2_10f["benign_exact_predicate_matches"] == 0
    assert p2_10f["benign_parse_errors"] == 0
    assert p2_10f["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"


    p2_10g = data["remediations"][6]
    assert p2_10g["remediation_id"] == "p2-10g-hidden-run-key"
    assert p2_10g["attack_scenario_hits_before"] == 8
    assert p2_10g["attack_scenario_hits_after"] == 9
    assert p2_10g["benign_events_scanned"] == 732200
    assert p2_10g["benign_sysmon_records_scanned"] == 732200
    assert p2_10g["benign_sysmon_chunks_scanned"] == 11894
    assert p2_10g["benign_sysmon_event13_scanned"] == 214572
    assert p2_10g["benign_run_or_runonce_targets"] == 18
    assert p2_10g["benign_hidden_run_targets"] == 0
    assert p2_10g["benign_exact_predicate_matches"] == 0
    assert p2_10g["benign_parse_errors"] == 0
    assert p2_10g["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"


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
    assert data["current_evidence_id"] == "p2-10g-current-detection-evidence"
    assert [row["remediation_id"] for row in data["remediations"]] == [
        "p2-10a-scheduled-task-4698",
        "p2-10b-wmi-xsl",
        "p2-10c-domain-admins-4661",
        "p2-10d-lsass-access-1010",
        "p2-10e-winrm-wsmprovhost-child",
        "p2-10f-service-pathless-7045",
        "p2-10g-hidden-run-key",
    ]
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
