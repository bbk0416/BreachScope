from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_26c_gha_windows_benign_binding.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "p2_26c_benign_source_identity.yml"
RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_26c_binds_fresh_ephemeral_windows_source_before_collection() -> None:
    row = _load()
    assert row["status"] == "BOUND_PRE_COLLECTION"
    assert row["analysis_class"] == "pre_collection_fresh_external_ephemeral_windows_benign_binding"
    assert row["binding_base_commit"] == "5ea5c710ccdb7d6116380e2603ac1367a1ac23c9"
    detector = row["frozen_detector"]
    assert detector["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert detector["rules_tree_sha256"] == RULE_HASH
    assert detector["rule_count"] == 68
    assert detector["current_evidence_id"] == "p2-25-fresh-attack-revalidation-current-detection-evidence"


def test_p2_26c_source_population_and_channels_are_preregistered() -> None:
    source = _load()["source"]
    assert source["platform"] == "GitHub Actions hosted runner"
    assert source["runner_label"] == "windows-2025"
    assert source["source_class"] == "fresh_ephemeral_ci_windows_event_logs"
    assert source["collection_window"]["milliseconds"] == 900000

    channels = source["channels"]
    assert [(row["channel"], row["required"]) for row in channels] == [
        ("Security", True),
        ("System", True),
        ("Application", True),
        ("Windows PowerShell", False),
        ("Microsoft-Windows-PowerShell/Operational", False),
    ]


def test_p2_26c_collection_is_post_merge_pre_checkout_identity_only() -> None:
    row = _load()
    basis = row["selection_basis"]
    assert basis["exact_source_bytes_exist_before_binding"] is False
    assert basis["source_is_generated_only_after_binding_merge"] is True
    assert basis["source_previously_seen_by_breachscope"] is False
    assert basis["source_results_available_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False
    assert basis["repository_code_executed_before_source_collection"] is False
    assert basis["source_collection_occurs_before_repository_checkout"] is True

    protocol = row["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["repository_checkout_before_phase_b_collection"] == "prohibited"
    assert protocol["evtx_record_parsing_in_phase_b"] == "prohibited"
    assert protocol["detector_execution_in_phase_b"] == "prohibited"
    assert protocol["phase_b_rerun_allowed"] is False
    assert protocol["first_completed_or_failed_phase_b_execution_is_canonical"] is True
    assert protocol["phase_c_duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_phase_c_execution_is_canonical"] is True
    assert protocol["tuning_between_phase_b_and_phase_c_allowed"] is False


def test_p2_26c_identity_workflow_cannot_run_on_pull_request() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "branches: [main]" in text
    assert '.github/workflows/p2_26c_benign_source_identity.yml' in text
    assert "pull_request:" not in text
    assert "workflow_dispatch:" not in text
    assert "actions/checkout@" not in text
    assert "runs-on: windows-2025" in text
    assert 'timediff(@SystemTime) <= 900000' in text
    assert "wevtutil epl" in text
    assert "evtx_records_parsed = $false" in text
    assert "breachscope_detector_executed = $false" in text
    assert "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f" in text


def test_p2_26c_claims_remain_bounded_before_measurement() -> None:
    row = _load()
    ground = row["source_ground_truth"]
    assert ground["population_intent"] == "BENIGN_CI_BASELINE"
    assert ground["event_level_labels"] == "NOT_AVAILABLE"
    assert ground["confirmed_false_positive_labels"] == "NOT_AVAILABLE"
    assert ground["malware_free_guarantee_by_platform"] == "NOT_CLAIMED"
    assert ground["production_workstation_representativeness"] == "NOT_ESTABLISHED"

    scoring = row["planned_scoring"]
    assert scoring["metric_name"] == "observed_source_intent_benign_flagged_event_fraction"
    assert scoring["aggregate"] == "unique_flagged_events / parsed_events"
    assert scoring["confirmed_false_positive_rate"] == "NOT_MEASURED"
    assert scoring["production_false_positive_rate"] == "NOT_CLAIMED"

    claim = row["claim_boundary"]
    assert claim["fresh_benign_revalidation"] == "NOT_YET_MEASURED"
    assert claim["exact_source_identity"] == "NOT_YET_COLLECTED"
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["general_fresh_full_benign_fpr"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
