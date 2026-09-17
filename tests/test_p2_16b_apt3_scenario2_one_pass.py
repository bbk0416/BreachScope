from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_16b_apt3_scenario2_one_pass.yaml"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_16b_7fc2fc92" / "measurement.json"


def _evidence() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def _measurement() -> dict:
    return json.loads(MEASUREMENT.read_text(encoding="utf-8"))


def test_measurement_sha_is_bound() -> None:
    evidence = _evidence()
    actual = hashlib.sha256(MEASUREMENT.read_bytes()).hexdigest()
    assert actual == evidence["measurement"]["sha256"]


def test_one_pass_counts_are_exact() -> None:
    row = _measurement()
    assert row["measurement_repo_commit"] == "7fc2fc92d6be94da6384eee09f042807366617ab"
    assert (row["events"], row["parse_errors"]) == (121659, 0)
    assert (row["findings"], row["flagged_events"]) == (63683, 20394)
    assert row["chain_types"] == {"activity": 32}
    assert row["cross_host_chains"] == 0
    assert row["documented_hr001_hfdc01_chains"] == 0
    assert row["cross_host_scenarios"] == 0
    assert row["documented_hr001_hfdc01_scenarios"] == 0


def test_normalization_failure_is_recorded_without_repairing_result() -> None:
    evidence = _evidence()
    row = _measurement()
    coverage = row["canonical_coverage"]
    assert coverage["raw_computer_name_present"] == 121659
    assert coverage["raw_source_name_present"] == 121659
    assert coverage["raw_record_number_present"] == 121659
    assert coverage["source_nonempty"] == 0
    assert row["hosts"] == {"{'NAME': 'WECSERVER'}": 121659}
    assert evidence["normalization_observation"]["endpoint_identity_preserved"] is False


def test_emitted_scenario_is_not_counted_as_documented_transition() -> None:
    row = _measurement()
    assert row["scenarios"] == 1
    assert len(row["scenario_rows"]) == 1
    scenario = row["scenario_rows"][0]
    assert scenario["attack_stage"] == "lateral_movement"
    assert scenario["mitre_techniques"] == ["T1021.001"]
    assert scenario["hosts"] == ["{'NAME': 'WECSERVER'}"]
    assert row["documented_hr001_hfdc01_scenarios"] == 0


def test_protocol_and_claim_boundaries_remain_strict() -> None:
    evidence = _evidence()
    protocol = evidence["protocol"]
    assert protocol["product_or_rules_tuned_after_binding_before_measurement"] is False
    assert protocol["one_pass_measurement_completed"] is True
    assert protocol["same_corpus_rerun_after_result"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
    claims = evidence["claim_boundary"]
    assert claims["event_level_ground_truth"] == "NOT_AVAILABLE"
    for key, value in claims.items():
        if key != "event_level_ground_truth":
            assert value == "NOT_CLAIMED"
