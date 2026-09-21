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
    assert "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326" in proc.stdout


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
    assert data["schema"] == "breachscope.current_detection_evidence_verification.v10"
    assert data["current_evidence_id"] == "p2-26c-fresh-benign-revalidation-current-detection-evidence"
    assert data["current_rules_tree_sha256"] == "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    assert data["rule_file_count"] == 5
    assert data["base_attack_scenario_hits"] == 2
    assert data["current_attack_scenario_hits"] == 10
    assert data["current_attack_scenario_hits_applies_to_current_rulepack"] is False
    assert data["attack_scenario_total"] == 10
    assert data["fresh_attack_revalidation_after_current_rule_change"] == "COMPLETED"
    assert data["fresh_attack_fixture_hits"] == 6
    assert data["fresh_attack_fixture_total"] == 8
    assert data["fresh_attack_fixture_hit_rate"] == 0.75
    assert data["fresh_benign_revalidation_after_current_rule_change"] == "COMPLETED"
    assert data["fresh_benign_parsed_events"] == 1643
    assert data["fresh_benign_parse_errors"] == 0
    assert data["fresh_benign_flagged_events"] == 1
    assert data["fresh_benign_findings"] == 1
    assert data["fresh_benign_observed_flagged_event_fraction"] == 0.0006086427267194157
    assert data["fresh_benign_observed_flagged_event_percent"] == 0.06086427267194157
    assert data["historical_benign"]["events"] == 766623
    assert len(data["calibrations"]) == 7

    j = data["calibrations"][-2]
    assert j["calibration_id"] == "p2-11j-t1003-networkprovider-credential-capture"
    assert j["from_rules_tree_sha256"] == "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
    assert j["to_rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert j["scenario_hits_before"] == 8
    assert j["scenario_hits_after"] == 9
    assert j["scenario_total"] == 12
    assert j["events"] == 902
    assert j["rules"] == 66
    assert j["findings"] == 92
    assert j["flagged_events"] == 88
    assert j["benign_events_scanned"] == 732200
    assert j["benign_exact_predicate_matches"] == 0

    p20 = data["calibrations"][-1]
    assert p20["calibration_id"] == "p2-20-postholdout-coverage"
    assert p20["from_rules_tree_sha256"] == j["to_rules_tree_sha256"]
    assert p20["to_rules_tree_sha256"] == "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
    assert p20["dataset_hits_before"] == 1
    assert p20["dataset_hits_after"] == 5
    assert p20["dataset_total"] == 5
    assert p20["attack_result_is_posthoc"] is True
    assert p20["events"] == 21328
    assert p20["rules"] == 68
    assert p20["parse_errors"] == 0
    assert p20["benign_events_scanned"] == 2323
    assert p20["benign_exact_predicate_matches"] == 0
    assert p20["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"

    assert len(data["posthoc_remediations"]) == 1
    p24d = data["posthoc_remediations"][0]
    assert p24d["remediation_id"] == "p2-24d-rule-noise-remediation"
    assert p24d["from_rules_tree_sha256"] == p20["to_rules_tree_sha256"]
    assert p24d["to_rules_tree_sha256"] == data["current_rules_tree_sha256"]
    assert p24d["change_class"] == "posthoc_benign_noise_narrowing"
    assert p24d["p2_24c_development_data"] is True
    assert p24d["estimated_flagged_events_on_p2_24c_development_data"] == 570
    assert p24d["fresh_attack_revalidation"] == "NOT_RUN"
    assert p24d["fresh_benign_revalidation"] == "NOT_RUN"
    assert p24d["production_false_positive_rate"] == "NOT_CLAIMED"


    assert len(data["post_remediation_revalidations"]) == 2
    p25 = data["post_remediation_revalidations"][0]
    assert p25["revalidation_id"] == "p2-25-deepbluecli-fresh-attack"
    assert p25["detector_rules_tree_sha256"] == data["current_rules_tree_sha256"]
    assert p25["fixture_count"] == 8
    assert p25["hits"] == 6
    assert p25["misses"] == 2
    assert p25["errors"] == 0
    assert p25["fixture_hit_rate"] == 0.75
    assert p25["fixture_hit_rate_is_event_level_recall"] is False
    assert p25["event_level_recall"] == "NOT_CLAIMED"
    assert p25["production_recall"] == "NOT_CLAIMED"

    p26c = data["post_remediation_revalidations"][1]
    assert p26c["revalidation_id"] == "p2-26c-gha-windows-fresh-benign"
    assert p26c["detector_rules_tree_sha256"] == data["current_rules_tree_sha256"]
    assert p26c["parsed_events"] == 1643
    assert p26c["parse_errors"] == 0
    assert p26c["findings"] == 1
    assert p26c["flagged_events"] == 1
    assert p26c["observed_source_intent_benign_flagged_event_fraction"] == 0.0006086427267194157
    assert p26c["observed_source_intent_benign_flagged_event_percent"] == 0.06086427267194157
    assert p26c["flagged_events_are_confirmed_false_positives"] is False
    assert p26c["production_false_positive_rate"] == "NOT_CLAIMED"

    assert len(data["parser_maintenance"]) == 1
    p29 = data["parser_maintenance"][0]
    assert p29["maintenance_id"] == "p2-29-single-parse-evtx"
    assert p29["historical_p2_20_parser_blob"] == "42ce35bff10d0541d26e0a5181cfcd1ef9a459cc"
    assert p29["current_parser_blob"] == "34534bf8256ce658c5f05991c05045f7c5066816"
    assert p29["p2_25_records_compared"] == 450
    assert p29["p2_26c_records_compared"] == 1643
    assert p29["total_current_revalidation_records_compared"] == 2093
    assert p29["total_mismatches"] == 0
    assert p29["combined_normalized_digest_sha256"] == (
        "a22fb6b0cb9faed59ab2813629e6dea7625ccad7519c512d0b99e9587d7ec8d9"
    )
    assert p29["current_evidence_id_changed"] is False
    assert p29["rules_tree_changed"] is False
    assert p29["speedup"] == "NOT_YET_FORMALLY_MEASURED"


def test_current_chain_keeps_claim_boundaries_explicit() -> None:
    data = yaml.safe_load(CURRENT_CHAIN.read_text(encoding="utf-8"))
    assert data["schema"] == "breachscope.current_detection_evidence_chain.v1"
    assert data["current_evidence_id"] == "p2-26c-fresh-benign-revalidation-current-detection-evidence"
    assert data["current_frozen_detector"] == {
        "repo_commit": "66f5d2e0061ea34113038a712597113a6df7bd63",
        "rules_tree_sha256": "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326",
        "rule_count": 68,
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
    assert data["posthoc_remediations"] == [
        {
            "remediation_id": "p2-24d-rule-noise-remediation",
            "diagnosis_record": "external_baseline/p2_24d_posthoc_rule_noise_diagnosis.yaml",
            "change_class": "posthoc_benign_noise_narrowing",
            "from_rules_tree_sha256": "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075",
            "to_rules_tree_sha256": "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326",
            "fresh_attack_revalidation": "NOT_RUN",
            "fresh_benign_revalidation": "NOT_RUN",
        }
    ]
    assert data["parser_maintenance"] == [
        {
            "maintenance_id": "p2-29-single-parse-evtx",
            "record": "external_baseline/p2_29_single_parse_parser_maintenance.yaml",
            "change_class": "semantics_preserving_parser_performance_refactor",
            "from_git_blob_sha1": "42ce35bff10d0541d26e0a5181cfcd1ef9a459cc",
            "to_git_blob_sha1": "34534bf8256ce658c5f05991c05045f7c5066816",
            "current_evidence_id_changed": False,
            "rules_tree_changed": False,
            "normalized_event_semantics": "PRESERVED_BY_EQUIVALENCE_CHECKS",
        }
    ]
    assert data["post_remediation_revalidations"] == [
        {
            "revalidation_id": "p2-25-deepbluecli-fresh-attack",
            "class": "fresh_external_attack_fixture_revalidation",
            "binding_record": "external_baseline/p2_25_deepblue_attack_binding.yaml",
            "contract_record": "external_baseline/p2_25_deepblue_attack_one_pass_contract.yaml",
            "result_record": "external_baseline/results/p2_25_e712fc7/result.yaml",
            "measurement_record": "external_baseline/results/p2_25_e712fc7/result.json",
            "detector_rules_tree_sha256": "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326",
            "fixture_count": 8,
            "hits": 6,
            "misses": 2,
            "errors": 0,
            "fixture_hit_rate": 0.75,
            "event_level_ground_truth": "NOT_AVAILABLE",
            "fixture_hit_rate_is_event_level_recall": False,
            "fresh_attack_revalidation": "COMPLETED",
        },
        {
            "revalidation_id": "p2-26c-gha-windows-fresh-benign",
            "class": "fresh_external_ephemeral_ci_benign_revalidation",
            "binding_record": "external_baseline/p2_26c_gha_windows_benign_binding.yaml",
            "contract_record": "external_baseline/p2_26c_gha_windows_benign_one_pass_contract.yaml",
            "result_record": "external_baseline/results/p2_26c_81b839d/result.yaml",
            "measurement_record": "external_baseline/results/p2_26c_81b839d/result.json",
            "detector_rules_tree_sha256": "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326",
            "parsed_events": 1643,
            "parse_errors": 0,
            "findings": 1,
            "flagged_events": 1,
            "observed_source_intent_benign_flagged_event_fraction": 0.0006086427267194157,
            "observed_source_intent_benign_flagged_event_percent": 0.06086427267194157,
            "event_level_ground_truth": "NOT_AVAILABLE",
            "flagged_events_are_confirmed_false_positives": False,
            "fresh_benign_revalidation": "COMPLETED",
            "production_false_positive_rate": "NOT_CLAIMED",
        }
    ]
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
