from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "current_detection_evidence.yaml"


def test_p2_13e_current_detection_evidence_chain_is_current_and_bounded():
    data = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))

    assert data["current_evidence_id"] == "p2-11j-current-detection-evidence"
    assert data["current_frozen_detector"] == {
        "repo_commit": "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb",
        "rules_tree_sha256": "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92",
        "rule_count": 66,
        "rule_file_count": 4,
    }

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
