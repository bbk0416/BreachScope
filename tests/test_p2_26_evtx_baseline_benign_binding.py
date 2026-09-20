from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_26_evtx_baseline_benign_binding.yaml"
RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
ASSET_SHA256 = "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_26_binds_unused_goodware_source_before_observation() -> None:
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_benign_corpus_binding"
    assert row["binding_base_commit"] == "2ca3d29c2054c78c5471634ede3b5a9b2b617e75"
    assert row["code_under_observation"]["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert row["code_under_observation"]["rules_tree_sha256"] == RULE_HASH
    assert row["code_under_observation"]["rule_count"] == 68
    assert row["source"]["repository"] == "NextronSystems/evtx-baseline"
    assert row["source"]["pinned_commit"] == "394bd48339f84b16053ad4804b894ab00c8a6c74"
    assert row["source"]["license"]["spdx"] == "Apache-2.0"

    basis = row["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["breachscope_default_branch_search_hits_for_source_names"] == 0
    assert basis["release_asset_downloaded_before_binding"] is False
    assert basis["release_archive_opened_before_binding"] is False
    assert basis["evtx_members_extracted_before_binding"] is False
    assert basis["evtx_member_bytes_opened_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False


def test_p2_26_pins_exact_release_asset_and_upstream_goodware_label() -> None:
    row = _load()
    release = row["source"]["release"]
    assert release["tag"] == "v0.8.5"
    assert release["asset_name"] == "win10-client.tgz"
    assert release["asset_sha256"] == ASSET_SHA256
    assert release["asset_size_bytes"] == "NOT_MEASURED_BEFORE_BINDING"

    ground = row["source_ground_truth"]
    assert ground["source_level_label"] == "GOODWARE_NORMAL_ACTIVITY"
    assert ground["event_level_labels"] == "NOT_AVAILABLE"
    assert ground["confirmed_false_positive_labels"] == "NOT_AVAILABLE"
    assert ground["production_representativeness"] == "NOT_ESTABLISHED"


def test_p2_26_requires_inventory_and_contract_before_any_evtx_parse() -> None:
    protocol = _load()["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["evtx_record_parsing_before_phase_c_contract"] == "prohibited"
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["no_result_driven_remeasurement"] is True
    assert "exact EVTX member inventory" in protocol["phase_c_required_before_data_content_observation"]


def test_p2_26_scoring_is_source_intent_flag_fraction_not_confirmed_fpr() -> None:
    row = _load()
    scoring = row["planned_scoring"]
    assert scoring["unit"] == "parsed_event"
    assert scoring["aggregate"] == "unique_flagged_events / parsed_events"
    assert scoring["name"] == "observed_source_intent_benign_flagged_event_fraction"
    assert scoring["confirmed_false_positive_rate"] == "NOT_MEASURED"
    assert scoring["production_false_positive_rate"] == "NOT_CLAIMED"

    claim = row["claim_boundary"]
    assert claim["fresh_benign_revalidation"] == "NOT_YET_MEASURED"
    assert claim["event_level_benign_ground_truth"] == "NOT_AVAILABLE"
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
