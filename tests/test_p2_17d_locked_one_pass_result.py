import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_17d_locked_one_pass_result.yaml"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_17c_b842066" / "measurement.json"


def load_evidence():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def load_measurement():
    return json.loads(MEASUREMENT.read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_measurement_artifact_is_bound_and_completed():
    row = load_evidence()
    measurement = load_measurement()
    assert measurement["status"] == "completed"
    assert sha256(MEASUREMENT) == row["measurement"]["stored_sha256"]
    assert row["measurement"]["original_sha256"] == "b3eb5243e6eb4b09b4887d7395f16328006fc264e77031f027e2c1816225f26e"
    assert row["measurement"]["storage_normalization"] == "CRLF_TO_LF_ONLY"


def test_result_matches_preregistered_hit_contract():
    row = load_evidence()
    measurement = load_measurement()
    assert row["summary"]["dataset_count"] == 5
    assert row["summary"]["hits"] == 1
    assert row["summary"]["misses_or_errors"] == 4
    assert row["summary"]["path_label_dataset_hit_rate"] == 0.2
    assert measurement["summary"]["hits"] == 1
    assert measurement["summary"]["misses_or_errors"] == 4
    assert [item["dataset_status"] for item in measurement["datasets"]] == [
        "MISS", "MISS", "MISS", "MISS", "HIT"
    ]


def test_parser_failures_remain_failures():
    rows = {item["technique_id"]: item for item in load_evidence()["datasets"]}
    assert rows["T1003.001"]["expected_technique_present"] is True
    assert rows["T1003.001"]["parse_errors"] == 18
    assert rows["T1003.001"]["dataset_status"] == "MISS"
    assert rows["T1105"]["expected_technique_present"] is True
    assert rows["T1105"]["parse_errors"] == 10
    assert rows["T1105"]["dataset_status"] == "MISS"


def test_detector_misses_are_preserved():
    rows = {item["technique_id"]: item for item in load_evidence()["datasets"]}
    assert rows["T1021.006"]["findings"] == 0
    assert rows["T1021.006"]["expected_technique_present"] is False
    assert rows["T1087.002"]["observed_techniques"] == ["T1047"]
    assert rows["T1087.002"]["expected_technique_present"] is False


def test_claim_boundary_does_not_turn_20_percent_into_recall():
    claims = load_evidence()["claim_boundary"]
    assert claims["path_label_dataset_hit_rate"] == 0.2
    assert claims["path_label_dataset_hit_rate_is_event_level_recall"] is False
    for key in (
        "detection_precision", "detection_recall", "false_positive_rate",
        "chain_precision", "chain_recall", "scenario_accuracy", "production_quality",
    ):
        assert claims[key] == "NOT_CLAIMED"
