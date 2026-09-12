from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "external_baseline" / "p2_12e_apt29_day2_confirmatory_selection.yaml"


def _load():
    return yaml.safe_load(SELECTION.read_text(encoding="utf-8"))


def test_p2_12e_freezes_day2_metadata_without_opening_bytes_or_labels() -> None:
    d = _load()
    assert d["schema"] == "breachscope.p2_12e_confirmatory_selection.v1"
    assert d["evaluation_class"] == "confirmatory_same_campaign_holdout_pre_download"
    assert d["frozen_detector"] == {
        "repo_commit": "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb",
        "rules_tree_sha256": "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92",
        "rule_count": 66,
    }
    source = d["source_selection"]
    assert source["pinned_commit"] == "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
    assert source["archive_path"] == "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip"
    assert source["archive_git_blob_sha1"] == "15e1e9d2d88a729b832c6430fa285c3e87bb70e4"
    assert source["repository_reported_archive_size_bytes"] == 43033041


def test_p2_12e_does_not_claim_independent_freshness() -> None:
    d = _load()
    boundary = d["independence_boundary"]
    assert boundary["independent_external_source_from_day1"] is False
    assert boundary["same_repository_as_day1"] is True
    assert boundary["same_campaign_as_day1"] is True
    assert boundary["different_reserved_day_split"] is True
    assert boundary["classification"] == "confirmatory_same_campaign_holdout"
    assert d["claim_boundary"]["independent_fresh_external_holdout"] == "NOT_CLAIMED"


def test_p2_12e_pre_download_state_is_fail_closed() -> None:
    d = _load()
    state = d["selection_protocol"]
    assert state == {
        "archive_bytes_downloaded": False,
        "archive_payload_inspected": False,
        "archive_sha256_known": False,
        "day2_label_rows_inspected": False,
        "day2_expected_technique_ids_known": False,
        "detector_executed_on_day2": False,
        "detector_results_viewed": False,
        "day1_result_already_observed": True,
        "tuning_after_day1_before_day2_forbidden": True,
        "next_allowed_phase": "P2-12F_DAY2_BYTE_AND_LABEL_BINDING",
    }
    claims = d["claim_boundary"]
    assert claims["day2_result"] == "NOT_YET_MEASURED"
    assert claims["confirmatory_holdout_result"] == "NOT_YET_MEASURED"
    assert claims["production_recall"] == "NOT_CLAIMED"
