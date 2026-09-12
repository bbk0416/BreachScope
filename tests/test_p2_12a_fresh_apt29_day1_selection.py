from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "external_baseline" / "p2_12a_fresh_apt29_day1_selection.yaml"


def test_p2_12a_selection_is_frozen_before_byte_download() -> None:
    data = yaml.safe_load(SELECTION.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.p2_12a_fresh_external_selection.v1"
    assert data["selection_id"] == "p2-12a-otrf-apt29-day1-v1"
    assert data["evaluation_class"] == "fresh_external_holdout_candidate"
    assert data["frozen_detector"]["repo_commit"] == (
        "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
    )
    assert data["frozen_detector"]["rules_tree_sha256"] == (
        "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    )
    assert data["frozen_detector"]["rule_count"] == 66

    source = data["source"]
    assert source["repository"] == "OTRF/Security-Datasets"
    assert source["pinned_commit"] == (
        "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
    )
    assert source["dataset_family"] == "compound/apt29"
    assert source["atomic_red_team_source"] is False

    policy = data["selection_policy"]
    assert policy["detector_results_consulted_before_selection"] is False
    assert policy["selected_archive_bytes_downloaded_before_selection"] is False
    assert policy["selected_archive_contents_inspected_before_selection"] is False

    corpus = data["selected_corpus"]
    assert corpus["scenario_id"] == "otrf-apt29-day1"
    assert corpus["source_path"] == (
        "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip"
    )
    assert corpus["git_blob_sha1"] == "7352679a173ec0310f9d0ed587782545182dd394"
    assert corpus["repository_reported_size_bytes"] == 13944973


def test_p2_12a_requires_byte_and_label_binding_before_detection() -> None:
    data = yaml.safe_load(SELECTION.read_text(encoding="utf-8"))
    protocol = data["protocol"]

    assert protocol["phase_a_selection_frozen_before_byte_download"] is True
    assert protocol["phase_b_byte_binding_required_before_detection"] is True
    assert protocol["phase_b_label_binding_required_before_detection"] is True
    assert protocol["detection_must_not_run_until_byte_and_label_binding_committed"] is True
    assert protocol["archive_sha256"] == "PENDING_P2_12B"
    assert protocol["expected_technique_binding"] == "PENDING_P2_12B"
    assert protocol["event_level_labels"] == "NOT_ASSUMED"
    assert protocol["precision_recall_fpr"] == "NOT_CLAIMED"
    assert protocol["day2_reserved_unseen_for_future_validation"] is True


def test_p2_12a_does_not_claim_results_before_measurement() -> None:
    data = yaml.safe_load(SELECTION.read_text(encoding="utf-8"))
    claims = data["claim_boundary"]

    assert claims["fresh_external_holdout_result"] == "NOT_YET_MEASURED"
    assert claims["production_detection_rate"] == "NOT_CLAIMED"
    assert claims["production_precision"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
