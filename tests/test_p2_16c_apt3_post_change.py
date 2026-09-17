from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_16c_apt3_post_change.yaml"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_16c_7588b806" / "measurement.json"


def _evidence() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def _measurement() -> dict:
    return json.loads(MEASUREMENT.read_text(encoding="utf-8"))


def test_measurement_sha_is_bound() -> None:
    evidence = _evidence()
    actual = hashlib.sha256(MEASUREMENT.read_bytes()).hexdigest()
    assert actual == evidence["measurement"]["sha256"]


def test_post_change_counts_are_exact() -> None:
    row = _measurement()
    assert row["measurement_repo_commit"] == "7588b8064912cc562c2ec673d32881ecace457c5"
    assert (row["events"], row["parse_errors"]) == (121659, 0)
    assert (row["findings"], row["flagged_events"]) == (114446, 37909)
    assert row["hosts"] == {
        "ACCT001": 1542,
        "HFDC01": 28148,
        "HR001": 85957,
        "IT001": 6012,
    }
    assert row["chain_types"] == {
        "activity": 34,
        "download_exec": 2,
        "encoded_exec": 12,
    }
    assert row["cross_host_chains"] == 0
    assert row["documented_hr001_hfdc01_chains"] == 0
    assert row["cross_host_scenarios"] == 0
    assert row["documented_hr001_hfdc01_scenarios"] == 0


def test_endpoint_identity_is_preserved() -> None:
    evidence = _evidence()
    row = _measurement()
    coverage = row["canonical_coverage"]
    assert coverage["host_nonempty"] == 121659
    assert coverage["source_nonempty"] == 121659
    assert evidence["post_change_observation"]["endpoint_identity_preserved"] is True
    assert evidence["post_change_observation"]["collector_identity_used_as_endpoint"] is False


def test_documented_transition_is_still_not_reconstructed() -> None:
    evidence = _evidence()
    row = _measurement()
    assert row["documented_hr001_hfdc01_chains"] == 0
    assert row["documented_hr001_hfdc01_scenarios"] == 0
    observation = evidence["post_change_observation"]
    assert observation["documented_hr001_to_hfdc01_transition_reconstructed"] is False


def test_protocol_and_claim_boundaries_remain_strict() -> None:
    evidence = _evidence()
    protocol = evidence["protocol"]
    assert protocol["source_corpus_previously_observed"] is True
    assert protocol["development_informed_by_prior_result"] is True
    assert protocol["blind_evaluation"] is False
    assert protocol["independent_holdout"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
    assert protocol["p2_14e_artifacts_modified"] is False
    claims = evidence["claim_boundary"]
    assert claims["event_level_ground_truth"] == "NOT_AVAILABLE"
    for key, value in claims.items():
        if key != "event_level_ground_truth":
            assert value == "NOT_CLAIMED"
