from pathlib import Path

import yaml


RECORD = Path("external_baseline/p2_13d_win11_benign_alert_adjudication.yaml")


def test_p2_13d_adjudication_record_is_fail_closed():
    data = yaml.safe_load(RECORD.read_text(encoding="utf-8"))

    assert data["execution"]["run_id"] == 34764978817
    assert data["execution"]["canonical_artifact_id"] == 10320797645
    assert data["execution"]["aggregate_status"] == "success"
    assert data["execution"]["shard_jobs_successful"] == 16

    assert data["frozen_detector"]["repo_commit"] == "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
    assert data["frozen_detector"]["rule_count"] == 66

    reproduced = data["measurement_reproduced"]
    assert reproduced == {
        "findings": 54,
        "flagged_events": 54,
        "detected_rule_count": 7,
        "complete_samples_collected": 54,
    }

    counts = data["adjudication"]["counts"]
    assert counts["benign_consistent"] == 50
    assert counts["indeterminate_sensitive_action"] == 4
    assert sum(counts.values()) == 54

    by_rule = data["adjudication"]["by_rule"]
    assert sum(entry["total"] for entry in by_rule.values()) == 54
    assert sum(entry["benign_consistent"] for entry in by_rule.values()) == 50
    assert sum(entry["indeterminate_sensitive_action"] for entry in by_rule.values()) == 4

    boundary = data["claim_boundary"]
    assert boundary["event_level_benign_ground_truth"] == "NOT_AVAILABLE"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["production_precision"] == "NOT_CLAIMED"
    assert boundary["production_recall"] == "NOT_CLAIMED"
    assert boundary["confirmed_false_positives"] == "NOT_CLAIMED"

    protocol = data["protocol"]
    assert protocol["detector_tuning_performed"] is False
    assert protocol["rule_changes_performed"] is False
    assert protocol["classification_changed_p2_13c_measurement"] is False
