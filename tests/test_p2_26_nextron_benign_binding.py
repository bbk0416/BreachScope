from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_26_nextron_benign_binding.yaml"
RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
ASSET_SHA = "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_26_binds_new_goodware_source_before_observation() -> None:
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_benign_archive_binding"
    assert row["frozen_detector"]["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert row["frozen_detector"]["rules_tree_sha256"] == RULE_HASH
    assert row["frozen_detector"]["rule_count"] == 68
    assert row["frozen_detector"]["current_evidence_commit"] == (
        "2ca3d29c2054c78c5471634ede3b5a9b2b617e75"
    )
    source = row["source"]
    assert source["repository"] == "NextronSystems/evtx-baseline"
    assert source["pinned_repository_commit"] == "394bd48339f84b16053ad4804b894ab00c8a6c74"
    assert source["readme"]["git_blob_sha1"] == "0e71f1bf21374b08432711db22aa50ec100f80ef"
    assert source["license"] == "Apache-2.0"
    assert "goodware evtx logs" in source["upstream_description"]


def test_p2_26_pins_release_asset_without_opening_archive() -> None:
    row = _load()
    release = row["source"]["release"]
    assert release["tag"] == "v0.8.5"
    assert release["asset_name"] == "win10-client.tgz"
    assert release["asset_sha256"] == ASSET_SHA
    assert release["asset_size_display"] == "67.6 MB"
    assert release["asset_uploaded_at_utc"] == "2026-09-14T13:27:31Z"

    basis = row["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["breachscope_default_branch_search_hits_for_source_names"] == 0
    assert basis["release_metadata_observed_before_binding"] is True
    assert basis["asset_downloaded_before_binding"] is False
    assert basis["archive_opened_before_binding"] is False
    assert basis["archive_member_names_observed_before_binding"] is False
    assert basis["evtx_members_extracted_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False


def test_p2_26_goodware_label_is_source_intent_not_manual_event_truth() -> None:
    ground = _load()["source_ground_truth"]
    assert ground["archive_intent"] == "BENIGN_GOODWARE_BASELINE"
    assert ground["event_level_labels"] == "NOT_AVAILABLE"
    assert ground["manual_event_adjudication"] == "NOT_AVAILABLE"
    assert ground["confirmed_false_positive_labels"] == "NOT_AVAILABLE"


def test_p2_26_requires_contract_before_archive_listing_or_parse() -> None:
    protocol = _load()["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["planned_member_selection"].startswith("all regular archive members")
    assert protocol["archive_listing_before_phase_c_contract"] == "prohibited"
    assert protocol["archive_extraction_before_phase_c_contract"] == "prohibited"
    assert protocol["record_parse_before_phase_c_contract"] == "prohibited"
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["no_result_driven_remeasurement"] is True


def test_p2_26_scoring_is_flagged_fraction_not_confirmed_fpr() -> None:
    scoring = _load()["planned_scoring"]
    assert scoring["unit"] == "parsed_event"
    assert scoring["aggregate"] == "flagged_events / parsed_events"
    assert scoring["metric_name"] == "source_intent_benign_flagged_event_fraction"
    assert scoring["confirmed_false_positive_rate"] == "NOT_MEASURED"
    assert scoring["production_false_positive_rate"] == "NOT_CLAIMED"

    claim = _load()["claim_boundary"]
    assert claim["fresh_benign_revalidation"] == "NOT_YET_MEASURED"
    assert claim["source_intent_benign_flagged_event_fraction"] == "NOT_YET_MEASURED"
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
