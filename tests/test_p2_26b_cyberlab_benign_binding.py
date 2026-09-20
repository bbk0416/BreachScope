from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_26b_cyberlab_benign_binding.yaml"
RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
SOURCE_COMMIT = "a5f2c0dbe64b7201fdc2c47eb23efc119115d652"
SOURCE_SHA = "452d7f45bf0629a795cd413e200631eb3c8fcfef1327d3766014541aabe58c88"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_26b_binds_fresh_cyberlab_source_before_observation() -> None:
    row = _load()
    assert row["status"] == "BOUND_PRE_OBSERVATION"
    assert row["analysis_class"] == "pre_observation_external_benign_fixture_binding"
    assert row["binding_base_commit"] == "2fefbb4e19c1473304bb3fbeba019ddbbb44b41e"
    detector = row["frozen_detector"]
    assert detector["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert detector["rules_tree_sha256"] == RULE_HASH
    assert detector["rule_count"] == 68
    assert detector["current_evidence_id"] == "p2-25-fresh-attack-revalidation-current-detection-evidence"


def test_p2_26b_pins_exact_raw_evtx_identity_from_upstream_metadata() -> None:
    source = _load()["source"]
    assert source["repository"] == "project-cyberlab/cyberlab"
    assert source["pinned_repository_commit"] == SOURCE_COMMIT
    assert source["readme"]["git_blob_sha1"] == "6c57a7b0a918fc2694a2b362b4504e78191dc584"
    selected = source["selected_file"]
    assert selected["path"] == "modules/lab-linux/06-windows-artifact-libs/exercise/Security.evtx"
    assert selected["git_blob_sha1"] == "540677984c675604d9318ee9accc3ce823ea60f5"
    assert selected["size_bytes"] == 69632
    assert selected["upstream_declared_sha256"] == SOURCE_SHA
    assert source["source_bytes_will_be_redistributed_by_breachscope"] is False


def test_p2_26b_benign_label_is_direct_upstream_source_intent() -> None:
    ground = _load()["source_ground_truth"]
    assert ground["fixture_intent"] == "BENIGN_INERT_NORMAL_LOGON_LOGOFF"
    assert "isolated Windows 10 lab VM" in ground["label_basis"]
    assert "normal logon/logoff" in ground["label_basis"]
    assert ground["event_level_labels"] == "NOT_AVAILABLE"
    assert ground["manual_event_adjudication"] == "NOT_AVAILABLE"
    assert ground["confirmed_false_positive_labels"] == "NOT_AVAILABLE"


def test_p2_26b_is_fresh_and_bytes_remain_unobserved() -> None:
    basis = _load()["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["breachscope_default_branch_search_hits_for_source_names"] == 0
    assert basis["selected_file_previously_used_by_breachscope"] is False
    assert basis["selection_used_only_repository_metadata_and_readme_label"] is True
    assert basis["selected_file_bytes_downloaded_before_binding"] is False
    assert basis["selected_file_opened_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False
    assert basis["prior_p2_26_nextron_binding_aborted_as_duplicate"] is True


def test_p2_26b_requires_contract_before_parse_and_limits_claims() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["content_observation_before_phase_c_contract"] == "prohibited"
    assert protocol["record_parse_before_phase_c_contract"] == "prohibited"
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["no_result_driven_remeasurement"] is True

    scoring = row["planned_scoring"]
    assert scoring["metric_name"] == "source_intent_benign_flagged_event_fraction"
    assert scoring["aggregate"] == "flagged_events / parsed_events"
    assert scoring["confirmed_false_positive_rate"] == "NOT_MEASURED"
    assert scoring["production_false_positive_rate"] == "NOT_CLAIMED"

    claim = row["claim_boundary"]
    assert claim["fresh_benign_revalidation"] == "NOT_YET_MEASURED"
    assert claim["general_fresh_full_benign_fpr"] == "NOT_CLAIMED"
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
