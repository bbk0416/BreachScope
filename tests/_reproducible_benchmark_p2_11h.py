from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_SCRIPT = ROOT / "scripts" / "verify_reproducible_benchmark.py"
CURRENT_SCRIPT = ROOT / "scripts" / "verify_current_detection_evidence.py"
CURRENT_CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"
_HISTORICAL_TESTS = ROOT / "tests" / "_reproducible_benchmark_p2_11f.py"

_spec = importlib.util.spec_from_file_location("_p2_11f_reproducible_tests", _HISTORICAL_TESTS)
assert _spec is not None and _spec.loader is not None
_hist = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hist)

_OVERRIDES = {
    "test_historical_p2_09e_verifier_fails_closed_after_rule_drift",
    "test_current_detection_evidence_chain_verifies_without_network",
    "test_current_chain_keeps_claim_boundaries_explicit",
}
for _name in dir(_hist):
    if not _name.startswith("test_") or _name in _OVERRIDES:
        continue
    _fn = getattr(_hist, _name)
    if not callable(_fn):
        continue

    def _wrapper(_fn=_fn):
        return _fn()

    _wrapper.__name__ = _name
    _wrapper.__qualname__ = _name
    globals()[_name] = _wrapper


def _assert_subset(actual: dict, expected: dict) -> None:
    for key, value in expected.items():
        assert actual[key] == value


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
    assert "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec" in proc.stdout


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
    assert data["schema"] == "breachscope.current_detection_evidence_verification.v4"
    assert data["current_evidence_id"] == "p2-11h-current-detection-evidence"
    assert data["base_rules_tree_sha256"] == (
        "543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce"
    )
    assert data["current_rules_tree_sha256"] == (
        "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
    )
    assert data["rule_file_count"] == 4
    assert data["base_attack_scenario_hits"] == 2
    assert data["current_attack_scenario_hits"] == 10
    assert data["attack_scenario_total"] == 10
    assert data["historical_benign"]["events"] == 766623
    assert data["historical_benign"]["false_positives"] == 17
    assert data["historical_benign"]["true_negatives"] == 766606
    assert data["historical_benign"]["applies_to_rules_tree_sha256"] == data["base_rules_tree_sha256"]

    expected_remediations = [
        {"remediation_id": "p2-10a-scheduled-task-4698", "attack_scenario_hits_before": 2, "attack_scenario_hits_after": 3, "benign_non_sysmon_events_scanned": 34423, "benign_exact_predicate_matches": 0},
        {"remediation_id": "p2-10b-wmi-xsl", "attack_scenario_hits_before": 3, "attack_scenario_hits_after": 4, "benign_sysmon_records_scanned": 732200, "benign_raw_wmic_records": 29, "benign_exact_predicate_matches": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"remediation_id": "p2-10c-domain-admins-4661", "attack_scenario_hits_before": 4, "attack_scenario_hits_after": 5, "benign_non_sysmon_events_scanned": 34423, "benign_security_4661": 0, "benign_exact_predicate_matches": 0, "evaluator_control_scenario_hits": 4, "evaluator_control_findings": 5, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"remediation_id": "p2-10d-lsass-access-1010", "attack_scenario_hits_before": 5, "attack_scenario_hits_after": 6, "benign_sysmon_records_scanned": 732200, "benign_lsass_event10_target_matches": 61, "benign_exact_predicate_matches": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"remediation_id": "p2-10e-winrm-wsmprovhost-child", "attack_scenario_hits_before": 6, "attack_scenario_hits_after": 7, "benign_sysmon_records_scanned": 732200, "benign_sysmon_event1_scanned": 2149, "benign_exact_predicate_matches": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"remediation_id": "p2-10f-service-pathless-7045", "attack_scenario_hits_before": 7, "attack_scenario_hits_after": 8, "benign_events_scanned": 766623, "benign_evtx_files_scanned": 352, "benign_service_control_manager_7045_scanned": 26, "benign_pathless_imagepath_matches": 0, "benign_exact_predicate_matches": 0, "benign_parse_errors": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"remediation_id": "p2-10g-hidden-run-key", "attack_scenario_hits_before": 8, "attack_scenario_hits_after": 9, "benign_events_scanned": 732200, "benign_sysmon_records_scanned": 732200, "benign_sysmon_chunks_scanned": 11894, "benign_sysmon_event13_scanned": 214572, "benign_run_or_runonce_targets": 18, "benign_hidden_run_targets": 0, "benign_exact_predicate_matches": 0, "benign_parse_errors": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"remediation_id": "p2-10h-wmi-4688-parent-correlation", "attack_scenario_hits_before": 9, "attack_scenario_hits_after": 10, "benign_events_scanned": 34423, "benign_non_sysmon_events_scanned": 34423, "benign_security_4688": 78, "benign_parent_pid_resolved_within_300s": 64, "benign_wmiprvse_parent_children_wbem": 0, "benign_exact_predicate_matches": 0, "benign_parse_errors": 0, "analyzer_git_blob_sha1": "f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7", "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
    ]
    assert len(data["remediations"]) == len(expected_remediations)
    for actual, expected in zip(data["remediations"], expected_remediations, strict=True):
        _assert_subset(actual, expected)

    expected_calibrations = [
        {"calibration_id": "p2-11d-local-account-4720", "from_rules_tree_sha256": "371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f", "to_rules_tree_sha256": "b42725734f70cfc87ccd0122e6ab90da2169d7599b2abaaf22c27050efa0c4d2", "scenario_hits_before": 0, "scenario_hits_after": 2, "scenario_total": 12, "events": 902, "rules": 61, "findings": 84, "flagged_events": 80, "benign_events_scanned": 34423, "benign_exact_predicate_matches": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"calibration_id": "p2-11e-t1007-service-discovery", "from_rules_tree_sha256": "b42725734f70cfc87ccd0122e6ab90da2169d7599b2abaaf22c27050efa0c4d2", "to_rules_tree_sha256": "9b5d45c4f0edc37c788cda17451de6cf6b9114b8b6353c4522d15c294add053c", "scenario_hits_before": 2, "scenario_hits_after": 4, "scenario_total": 12, "events": 902, "rules": 63, "findings": 88, "flagged_events": 84, "benign_events_scanned": 732200, "benign_exact_predicate_matches": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"calibration_id": "p2-11f-t1006-direct-volume-access", "from_rules_tree_sha256": "9b5d45c4f0edc37c788cda17451de6cf6b9114b8b6353c4522d15c294add053c", "to_rules_tree_sha256": "1626aca8b7b9a8e2a7e1f42360c65b504827ff43e52159eb3716613ebb540a50", "scenario_hits_before": 4, "scenario_hits_after": 5, "scenario_total": 12, "events": 902, "rules": 64, "findings": 89, "flagged_events": 85, "benign_events_scanned": 732200, "benign_exact_predicate_matches": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"calibration_id": "p2-11g-t1027-encoded-powershell-mapping", "from_rules_tree_sha256": "1626aca8b7b9a8e2a7e1f42360c65b504827ff43e52159eb3716613ebb540a50", "to_rules_tree_sha256": "1626aca8b7b9a8e2a7e1f42360c65b504827ff43e52159eb3716613ebb540a50", "scenario_hits_before": 5, "scenario_hits_after": 6, "scenario_total": 12, "events": 902, "rules": 64, "findings": 89, "flagged_events": 85, "predicate_change": False, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
        {"calibration_id": "p2-11h-t1047-wmic-query", "from_rules_tree_sha256": "1626aca8b7b9a8e2a7e1f42360c65b504827ff43e52159eb3716613ebb540a50", "to_rules_tree_sha256": "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec", "scenario_hits_before": 6, "scenario_hits_after": 8, "scenario_total": 12, "events": 902, "rules": 65, "findings": 91, "flagged_events": 87, "benign_events_scanned": 732200, "benign_exact_predicate_matches": 0, "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED"},
    ]
    assert len(data["calibrations"]) == len(expected_calibrations)
    for actual, expected in zip(data["calibrations"], expected_calibrations, strict=True):
        _assert_subset(actual, expected)


def test_current_chain_keeps_claim_boundaries_explicit() -> None:
    data = yaml.safe_load(CURRENT_CHAIN.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.current_detection_evidence_chain.v1"
    assert data["current_evidence_id"] == "p2-11h-current-detection-evidence"
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
        "p2-11f-t1006-direct-volume-access",
        "p2-11g-t1027-encoded-powershell-mapping",
        "p2-11h-t1047-wmic-query",
    ]
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
