import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_17c_attack_data_one_pass_result.yaml"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_17b_34e4d444" / "measurement.json"
RUNNER = ROOT / "external_baseline" / "results" / "p2_17b_34e4d444" / "runner_used.py"


def _evidence():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def _measurement():
    return json.loads(MEASUREMENT.read_text(encoding="utf-8"))


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_canonical_artifact_hashes_are_bound():
    row = _evidence()["canonical_measurement"]
    assert _sha(MEASUREMENT) == row["sha256"]
    assert _sha(RUNNER) == row["runner_sha256"]


def test_canonical_result_is_exact_and_not_overclaimed():
    row = _evidence()
    measurement = _measurement()
    assert measurement["status"] == "completed"
    assert row["summary"] == {
        "dataset_count": 5,
        "expected_technique_hits": 5,
        "expected_technique_misses": 0,
        "path_label_dataset_hit_rate": 1.0,
        "parsed_events": 54334,
        "parse_errors": 73,
        "findings": 806,
        "flagged_events": 327,
    }
    assert all(item["expected_technique_hit"] for item in measurement["datasets"])
    assert sum(item["parse_errors"] for item in measurement["datasets"]) == 73


def test_protocol_overlap_is_preserved_not_hidden():
    protocol = _evidence()["protocol"]
    assert protocol["canonical_execution_is_earliest_substantive_execution"] is True
    assert protocol["later_overlapping_substantive_execution_observed"] is True
    assert protocol["later_duplicate_excluded_from_canonical_result"] is True
    assert protocol["strict_one_pass_execution_exclusivity"] is False
    assert protocol["product_or_rules_tuned_from_holdout_result"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False


def test_claim_boundary_keeps_dataset_hit_rate_narrow():
    claims = _evidence()["claim_boundary"]
    assert claims["path_label_dataset_hit_rate"] == 1.0
    assert claims["path_label_dataset_hit_rate_is_event_level_recall"] is False
    for key in ("detection_precision", "detection_recall", "false_positive_rate",
                "chain_precision", "chain_recall", "scenario_accuracy",
                "production_quality"):
        assert claims[key] == "NOT_CLAIMED"
