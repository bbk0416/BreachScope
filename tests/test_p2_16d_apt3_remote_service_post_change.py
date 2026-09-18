from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_16d_apt3_remote_service_post_change.yaml"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_16d_fad1b193" / "measurement.json"


def _evidence() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def _measurement() -> dict:
    return json.loads(MEASUREMENT.read_text(encoding="utf-8"))


def test_measurement_sha_is_bound() -> None:
    evidence = _evidence()
    actual = hashlib.sha256(MEASUREMENT.read_bytes()).hexdigest()
    assert actual == evidence["measurement"]["sha256"]


def test_recorded_measured_and_merged_tree_binding_is_exact() -> None:
    evidence = _evidence()["code_under_observation"]
    assert evidence["exact_tree_match"] is True
    # P2-16D records a measurement commit that was never made reachable from the
    # public repository. Fresh/shallow clones therefore validate the immutable
    # recorded tree identities instead of depending on historical local objects.
    assert evidence["measurement_repo_commit"] == "fad1b19328c73866d719ad0c77fb1e86e98505fa"
    assert evidence["merged_repo_commit"] == "f8538ead12121980638ca62e5497efe7190d7012"
    assert evidence["measurement_tree_sha"] == "5f9b638f28baa08f63b6c04f863f0a2ae6b50713"
    assert evidence["merged_tree_sha"] == "5f9b638f28baa08f63b6c04f863f0a2ae6b50713"


def test_posthoc_counts_are_exact() -> None:
    row = _measurement()
    assert row["measurement_repo_commit"] == "fad1b19328c73866d719ad0c77fb1e86e98505fa"
    assert (row["events"], row["parse_errors"]) == (121659, 0)
    assert (row["findings"], row["flagged_events"]) == (114446, 37909)
    assert row["chain_types"] == {
        "activity": 34,
        "download_exec": 2,
        "encoded_exec": 12,
        "remote_execution": 2,
    }
    assert row["cross_host_chains"] == 2
    assert row["documented_hr001_hfdc01_chains"] == 2
    assert row["cross_host_scenarios"] == 0
    assert row["documented_hr001_hfdc01_scenarios"] == 0


def test_remote_service_create_and_start_chains_are_exact() -> None:
    rows = _measurement()["documented_hr001_hfdc01_chain_rows"]
    assert len(rows) == 2
    create, start = rows
    assert create["event_count"] == 2
    assert create["finding_count"] == 0
    assert create["start_time"] == "2019-05-14T23:13:31.280000+00:00"
    assert create["end_time"] == "2019-05-14T23:13:31.356000+00:00"
    assert create["metadata"]["remote_execution"] == {
        "source_host": "HR001.shire.com",
        "target_host": "HFDC01.shire.com",
        "method": "scm",
        "operation": "create",
        "service_name": "AdobeUpdater",
    }
    assert start["event_count"] == 2
    assert start["finding_count"] == 0
    assert start["start_time"] == "2019-05-14T23:16:09.819000+00:00"
    assert start["end_time"] == "2019-05-14T23:16:09.942000+00:00"
    assert start["metadata"]["remote_execution"] == {
        "source_host": "HR001.shire.com",
        "target_host": "HFDC01.shire.com",
        "method": "scm",
        "operation": "start",
        "service_name": "AdobeUpdater",
    }


def test_protocol_and_claim_boundaries_remain_strict() -> None:
    evidence = _evidence()
    protocol = evidence["protocol"]
    assert protocol["independent_holdout"] is False
    assert protocol["development_informed_by_prior_result"] is True
    assert protocol["p2_16b_independent_result_replaced"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
    claims = evidence["claim_boundary"]
    assert claims["event_level_ground_truth"] == "NOT_AVAILABLE"
    for key, value in claims.items():
        if key != "event_level_ground_truth":
            assert value == "NOT_CLAIMED"
