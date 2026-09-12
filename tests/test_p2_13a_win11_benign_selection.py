from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "external_baseline" / "p2_13a_win11_benign_selection.yaml"


def test_p2_13a_selection_is_pre_download_and_pre_score() -> None:
    data = yaml.safe_load(SELECTION.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.p2_13a_win11_benign_selection.v1"
    assert data["selection_class"] == "fresh_benign_by_source_intent_pre_download"
    assert data["selected_before_archive_download"] is True
    assert data["selected_before_detector_execution"] is True

    source = data["source"]
    assert source["repository"] == "NextronSystems/evtx-baseline"
    assert source["release_tag"] == "v0.8.4"
    assert source["asset_name"] == "win11-client-2023.tgz"
    assert source["asset_id"] == 371539645
    assert source["asset_size_bytes"] == 169460461
    assert source["github_digest_sha256"] == "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"

    freshness = data["freshness_boundary"]
    assert freshness["prior_benign_corpus_seen"]["asset_name"] == "win10-client.tgz"
    assert freshness["selected_asset_previously_scored_by_breachscope"] is False
    assert freshness["selected_asset_bytes_downloaded_before_selection"] is False
    assert freshness["selected_asset_detector_results_consulted_before_selection"] is False

    detector = data["frozen_detector"]
    assert detector["repo_commit"] == "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
    assert detector["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert detector["rule_count"] == 66
    assert detector["rule_file_count"] == 4

    planned = data["planned_measurement"]
    assert planned["run_full_rulepack"] is True
    assert planned["parse_all_available_evtx_files"] is True
    assert planned["tune_detector_after_result"] is False

    boundary = data["claim_boundary"]
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["production_precision"] == "NOT_CLAIMED"
    assert boundary["production_recall"] == "NOT_CLAIMED"
    assert boundary["independent_benign_population"] == "NOT_CLAIMED"
