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
    assert "9b5d45c4f0edc37c788cda17451de6cf6b9114b8b6353c4522d15c294add053c" in proc.stdout


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
    assert data["schema"] == "breachscope.current_detection_evidence_verification.v3"
    assert data["base_rules_tree_sha256"] == (
        "543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce"
    )
    assert data["current_rules_tree_sha256"] == (
        "9b5d45c4f0edc37c788cda17451de6cf6b9114b8b6353c4522d15c294add053c"
    )
    assert data["rule_file_count"] == 4
    assert data["base_attack_scenario_hits"] == 2
    assert data["current_attack_scenario_hits"] == 10
    assert data["attack_scenario_total"] == 10
    assert data["historical_benign"]["events"] == 766623
    assert data["historical_benign"]["false_positives"] == 17
    assert data["historical_benign"]["true_negatives"] == 766606
    assert data["historical_benign"]["applies_to_rules_tree_sha256"] == data["base_rules_tree_sha256"]
    assert len(data["remediations"]) == 8

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

    p2_10h = data["remediations"][7]
    assert p2_10h["remediation_id"] == "p2-10h-wmi-4688-parent-correlation"
    assert p2_10h["attack_scenario_hits_before"] == 9
    assert p2_10h["attack_scenario_hits_after"] == 10
    assert p2_10h["benign_events_scanned"] == 34423
    assert p2_10h["benign_non_sysmon_events_scanned"] == 34423
    assert p2_10h["benign_security_4688"] == 78
    assert p2_10h["benign_parent_pid_resolved_within_300s"] == 64
    assert p2_10h["benign_wmiprvse_parent_children_wbem"] == 0
    assert p2_10h["benign_exact_predicate_matches"] == 0
    assert p2_10h["benign_parse_errors"] == 0
    assert p2_10h["analyzer_git_blob_sha1"] == "f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7"
    assert p2_10h["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"

    assert len(data["calibrations"]) == 2
    p2_11d = data["calibrations"][0]
    assert p2_11d["calibration_id"] == "p2-11d-local-account-4720"
    assert p2_11d["from_rules_tree_sha256"] == "371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f"
    assert p2_11d["to_rules_tree_sha256"] == "b42725734f70cfc87ccd0122e6ab90da2169d7599b2abaaf22c27050efa0c4d2"
    assert p2_11d["scenario_hits_before"] == 0
    assert p2_11d["scenario_hits_after"] == 2
    assert p2_11d["scenario_total"] == 12
    assert p2_11d["events"] == 902
    assert p2_11d["rules"] == 61
    assert p2_11d["findings"] == 84
    assert p2_11d["flagged_events"] == 80
    assert p2_11d["benign_events_scanned"] == 34423
    assert p2_11d["benign_exact_predicate_matches"] == 0
    assert p2_11d["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"

    p2_11e = data["calibrations"][1]
    assert p2_11e["calibration_id"] == "p2-11e-t1007-service-discovery"
    assert p2_11e["from_rules_tree_sha256"] == "b42725734f70cfc87ccd0122e6ab90da2169d7599b2abaaf22c27050efa0c4d2"
    assert p2_11e["to_rules_tree_sha256"] == "9b5d45c4f0edc37c788cda17451de6cf6b9114b8b6353c4522d15c294add053c"
    assert p2_11e["scenario_hits_before"] == 2
    assert p2_11e["scenario_hits_after"] == 4
    assert p2_11e["scenario_total"] == 12
    assert p2_11e["events"] == 902
    assert p2_11e["rules"] == 63
    assert p2_11e["findings"] == 88
    assert p2_11e["flagged_events"] == 84
    assert p2_11e["benign_events_scanned"] == 732200
    assert p2_11e["benign_exact_predicate_matches"] == 0
    assert p2_11e["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"


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
    assert data["current_evidence_id"] == "p2-11e-current-detection-evidence"
    assert [row["remediation_id"] for row in data["remediations"]] == [
        "p2-10a-scheduled-task-4698",
        "p2-10b-wmi-xsl",
        "p2-10c-domain-admins-4661",
        "p2-10d-lsass-access-1010",
        "p2-10e-winrm-wsmprovhost-child",
        "p2-10f-service-pathless-7045",
        "p2-10g-hidden-run-key",
        "p2-10h-wmi-4688-parent-correlation",
    ]
    assert [row["calibration_id"] for row in data["calibrations"]] == [
        "p2-11d-local-account-4720",
        "p2-11e-t1007-service-discovery",
    ]
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
