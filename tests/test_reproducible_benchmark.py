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
_HISTORICAL_TESTS = ROOT / "tests" / "_reproducible_benchmark_p2_11h.py"

_spec = importlib.util.spec_from_file_location("_p2_11h_reproducible_tests", _HISTORICAL_TESTS)
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
    assert "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88" in proc.stdout


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
    assert data["schema"] == "breachscope.current_detection_evidence_verification.v13"
    assert data["current_evidence_id"] == "independent-command-coverage-remediation-current-detection-evidence"
    assert data["current_rules_tree_sha256"] == (
        "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
    )
    assert data["rule_file_count"] == 5
    assert data["base_attack_scenario_hits"] == 2
    assert data["current_attack_scenario_hits"] == 10
    assert data["current_attack_scenario_hits_applies_to_current_rulepack"] is False
    assert data["attack_scenario_total"] == 10
    assert data["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert data["fresh_benign_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert data["prior_revalidations_apply_to_current_rulepack"] is False

    assert data["prior_attack_fixture_hits"] == 6
    assert data["prior_attack_fixture_total"] == 8
    assert data["prior_attack_fixture_hit_rate"] == 0.75
    assert data["prior_benign_parsed_events"] == 1643
    assert data["prior_benign_parse_errors"] == 0
    assert data["prior_benign_flagged_events"] == 1
    assert data["prior_benign_findings"] == 1
    assert data["prior_benign_observed_flagged_event_fraction"] == 0.0006086427267194157
    assert data["prior_benign_observed_flagged_event_percent"] == 0.06086427267194157

    assert data["historical_benign"]["events"] == 766623
    assert len(data["calibrations"]) == 7

    j = data["calibrations"][-2]
    assert j["calibration_id"] == "p2-11j-t1003-networkprovider-credential-capture"
    assert j["from_rules_tree_sha256"] == "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
    assert j["to_rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert j["scenario_hits_before"] == 8
    assert j["scenario_hits_after"] == 9
    assert j["benign_exact_predicate_matches"] == 0

    p20 = data["calibrations"][-1]
    assert p20["calibration_id"] == "p2-20-postholdout-coverage"
    assert p20["from_rules_tree_sha256"] == j["to_rules_tree_sha256"]
    assert p20["to_rules_tree_sha256"] == "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
    assert p20["dataset_hits_before"] == 1
    assert p20["dataset_hits_after"] == 5
    assert p20["dataset_total"] == 5

    assert len(data["posthoc_remediations"]) == 3
    p24d = data["posthoc_remediations"][0]
    assert p24d["remediation_id"] == "p2-24d-rule-noise-remediation"
    assert p24d["from_rules_tree_sha256"] == p20["to_rules_tree_sha256"]
    assert p24d["to_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert p24d["fresh_attack_revalidation"] == "NOT_RUN"
    assert p24d["fresh_benign_revalidation"] == "NOT_RUN"

    p35i = data["posthoc_remediations"][1]
    assert p35i["remediation_id"] == "p2-35i-original-filename-masquerading-remediation"
    assert p35i["from_rules_tree_sha256"] == p24d["to_rules_tree_sha256"]
    assert p35i["to_rules_tree_sha256"] == "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    assert p35i["rule_count_before"] == 68
    assert p35i["rule_count_after"] == 69
    assert p35i["socbed_known_gap_findings"] == 1
    assert p35i["atomic_refined_predicate_hits"] == 9
    assert p35i["nextron_refined_predicate_hits"] == 0
    assert p35i["fresh_attack_revalidation"] == "NOT_RUN"
    assert p35i["fresh_benign_revalidation"] == "NOT_RUN"

    cmdgap = data["posthoc_remediations"][2]
    assert cmdgap["remediation_id"] == "independent-command-coverage-remediation-v1"
    assert cmdgap["from_rules_tree_sha256"] == "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    assert cmdgap["to_rules_tree_sha256"] == data["current_rules_tree_sha256"]
    assert cmdgap["rule_count_before"] == 69
    assert cmdgap["rule_count_after"] == 73
    assert cmdgap["fresh_attack_revalidation"] == "NOT_RUN"
    assert cmdgap["fresh_benign_revalidation"] == "NOT_RUN"

    assert len(data["post_remediation_revalidations"]) == 3
    p25 = data["post_remediation_revalidations"][0]
    assert p25["revalidation_id"] == "p2-25-deepbluecli-fresh-attack"
    assert p25["detector_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert p25["detector_rules_tree_sha256"] != data["current_rules_tree_sha256"]
    assert p25["fixture_count"] == 8
    assert p25["hits"] == 6
    assert p25["misses"] == 2
    assert p25["fixture_hit_rate_is_event_level_recall"] is False

    p26c = data["post_remediation_revalidations"][1]
    assert p26c["revalidation_id"] == "p2-26c-gha-windows-fresh-benign"
    assert p26c["detector_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert p26c["detector_rules_tree_sha256"] != data["current_rules_tree_sha256"]
    assert p26c["parsed_events"] == 1643
    assert p26c["parse_errors"] == 0
    assert p26c["findings"] == 1
    assert p26c["flagged_events"] == 1
    assert p26c["flagged_events_are_confirmed_false_positives"] is False

    p35m = data["post_remediation_revalidations"][2]
    assert p35m["revalidation_id"] == "p2-35m-current-rulepack-fresh-source-revalidation"
    assert p35m["detector_rules_tree_sha256"] == "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    assert p35m["detector_rules_tree_sha256"] != data["current_rules_tree_sha256"]
    assert p35m["fixture_count"] == 10
    assert p35m["hits"] == 6
    assert p35m["misses"] == 4
    assert p35m["expected_technique_matches"] == 1
    assert p35m["expected_technique_match_fraction"] == 0.1
    assert p35m["fixture_hit_rate_is_event_level_recall"] is False
    assert p35m["benign_parsed_events"] == 425974
    assert p35m["benign_parse_errors"] == 12
    assert p35m["benign_findings"] == 4
    assert p35m["benign_flagged_events"] == 4
    assert p35m["flagged_events_are_confirmed_false_positives"] is False
    assert p35m["fresh_attack_revalidation"] == "COMPLETED"
    assert p35m["fresh_benign_revalidation"] == "COMPLETED"
    assert p35m["independent_source_family_holdout"] is False

    assert len(data["parser_maintenance"]) == 1
    p29 = data["parser_maintenance"][0]
    assert p29["maintenance_id"] == "p2-29-single-parse-evtx"
    assert p29["p2_25_records_compared"] == 450
    assert p29["p2_26c_records_compared"] == 1643
    assert p29["total_mismatches"] == 0
    assert p29["current_evidence_id_changed"] is False
    assert p29["rules_tree_changed"] is False

    validation = data["current_rulepack_validation"]
    assert validation["rule_change_id"] == "independent-command-coverage-remediation-v1"
    assert validation["current_revalidation_id"] == "NOT_RUN"
    assert validation["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert validation["fresh_benign_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert validation["prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack"] is False
    assert validation["prior_p2_35m_revalidation_applies_to_current_rulepack"] is False
    assert validation["fresh_current_rulepack_performance_available"] is False

def test_current_chain_keeps_claim_boundaries_explicit() -> None:
    data = yaml.safe_load(CURRENT_CHAIN.read_text(encoding="utf-8"))
    assert data["schema"] == "breachscope.current_detection_evidence_chain.v1"
    assert data["current_evidence_id"] == "independent-command-coverage-remediation-current-detection-evidence"
    assert data["current_frozen_detector"] == {
        "repo_commit": "bad0c88037d489f5b375c120002be74ac6082ffa",
        "rules_tree_sha256": "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88",
        "rule_count": 73,
        "rule_file_count": 5,
    }
    assert [row["calibration_id"] for row in data["calibrations"]] == [
        "p2-11d-local-account-4720",
        "p2-11e-t1007-service-discovery",
        "p2-11f-t1006-direct-volume-access",
        "p2-11g-t1027-encoded-powershell-mapping",
        "p2-11h-t1047-wmic-query",
        "p2-11j-t1003-networkprovider-credential-capture",
        "p2-20-postholdout-coverage",
    ]
    assert [row["remediation_id"] for row in data["posthoc_remediations"]] == [
        "p2-24d-rule-noise-remediation",
        "p2-35i-original-filename-masquerading-remediation",
        "independent-command-coverage-remediation-v1",
    ]
    assert data["posthoc_remediations"][0]["to_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert data["posthoc_remediations"][1]["from_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert data["posthoc_remediations"][1]["to_rules_tree_sha256"] == (
        "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    )
    assert data["post_remediation_revalidations"][0]["detector_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert data["post_remediation_revalidations"][1]["detector_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert data["current_rulepack_validation"] == {
        "rule_change_id": "independent-command-coverage-remediation-v1",
        "current_revalidation_id": "NOT_RUN",
        "fresh_attack_revalidation_after_current_rule_change": "NOT_RUN",
        "fresh_benign_revalidation_after_current_rule_change": "NOT_RUN",
        "prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack": False,
        "prior_p2_35m_revalidation_applies_to_current_rulepack": False,
        "fresh_current_rulepack_performance_available": False,
    }
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
