from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def test_p2_13e_current_detection_evidence_chain_is_current_and_bounded():
    data = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))

    assert data["current_evidence_id"] == "p2-26c-fresh-benign-revalidation-current-detection-evidence"
    assert data["current_frozen_detector"] == {
        "repo_commit": "66f5d2e0061ea34113038a712597113a6df7bd63",
        "rules_tree_sha256": "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326",
        "rule_count": 68,
        "rule_file_count": 5,
    }

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

    holdout = data["external_holdout_evidence"][0]
    assert holdout["closure_record"] == "external_baseline/p2_12_external_evidence_closure.yaml"
    assert holdout["day1"]["class"] == "fresh_external_holdout"
    assert holdout["day1"]["exact_legacy_id_overlap_count"] == 1
    assert holdout["day1"]["source_legacy_technique_total"] == 45
    assert holdout["day2"]["class"] == "confirmatory_same_campaign_holdout"
    assert holdout["day2"]["exact_legacy_id_overlap_count"] == 1
    assert holdout["day2"]["source_legacy_technique_total"] == 41
    assert holdout["combined_performance_metric"] == "NOT_COMPUTED"

    benign = data["benign_operational_evidence"][0]
    assert benign["measurement_record"] == "external_baseline/p2_13c_win11_benign_full_rulepack.yaml"
    assert benign["adjudication_record"] == "external_baseline/p2_13d_win11_benign_alert_adjudication.yaml"
    assert benign["parsed_records"] == 1741039
    assert benign["flagged_events"] == 54
    assert benign["adjudication"]["benign_consistent"] == 50
    assert benign["adjudication"]["indeterminate_sensitive_action"] == 4
    assert benign["adjudication"]["confirmed_false_positives"] == "NOT_CLAIMED"

    revalidation = data["post_remediation_revalidations"]
    assert revalidation == [
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

    boundary = data["claim_boundary"]
    for key in (
        "production_accuracy",
        "production_detection_rate",
        "production_false_positive_rate",
        "production_precision",
        "production_recall",
        "representative_production_population",
        "confirmed_false_positives",
        "fresh_full_benign_fpr_for_current_rulepack",
    ):
        assert boundary[key] == "NOT_CLAIMED"
    assert boundary["final_blind_holdout"] is False
    assert boundary["event_level_ground_truth"] == "NOT_AVAILABLE"
