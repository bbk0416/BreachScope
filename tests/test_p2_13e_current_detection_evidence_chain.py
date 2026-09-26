from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def test_p2_13e_current_detection_evidence_chain_is_current_and_bounded():
    data = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))

    assert data["current_evidence_id"] == "independent-command-coverage-remediation-current-detection-evidence"
    assert data["current_frozen_detector"] == {
        "repo_commit": "bad0c88037d489f5b375c120002be74ac6082ffa",
        "rules_tree_sha256": "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88",
        "rule_count": 73,
        "rule_file_count": 5,
    }

    assert [row["remediation_id"] for row in data["posthoc_remediations"]] == [
        "p2-24d-rule-noise-remediation",
        "p2-35i-original-filename-masquerading-remediation",
        "independent-command-coverage-remediation-v1",
    ]
    assert data["posthoc_remediations"][1]["detector_repo_commit"] == (
        "d53861ea1dca4a5cf2ed57e7d147ab04b244e7f4"
    )
    assert data["posthoc_remediations"][1]["to_rules_tree_sha256"] == (
        "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    )

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
    assert len(revalidation) == 3
    assert revalidation[:2] == [
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

    m = revalidation[2]
    assert m["revalidation_id"] == "p2-35m-current-rulepack-fresh-source-revalidation"
    assert m["detector_rules_tree_sha256"] == "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    assert m["detector_rules_tree_sha256"] != data["current_frozen_detector"]["rules_tree_sha256"]
    assert m["fixture_count"] == 10
    assert m["hits"] == 6
    assert m["misses"] == 4
    assert m["expected_technique_matches"] == 1
    assert m["benign_parsed_events"] == 425974
    assert m["benign_parse_errors"] == 12
    assert m["benign_flagged_events"] == 4
    assert m["fresh_attack_revalidation"] == "COMPLETED"
    assert m["fresh_benign_revalidation"] == "COMPLETED"
    assert m["independent_source_family_holdout"] is False

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
