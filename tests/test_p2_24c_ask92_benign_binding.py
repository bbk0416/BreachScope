from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_24c_ask92_sysmon_benign_binding.yaml"

MAIN = "dcd7f5bef9ae4e7be8e4d1a55d3a1fc3f3102766"
SOURCE_COMMIT = "ea164dee2ae71c9e9213a4167785095630723c38"
SOURCE_BLOB = "5b25c2dab0c87219fbce6d9ce3d2730257c650ec"
RULE_HASH = "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_24c_binds_unused_large_sysmon_evtx_before_observation() -> None:
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_benign_evtx_binding"
    assert row["code_under_observation"]["repo_commit"] == MAIN
    assert row["code_under_observation"]["rules_tree_sha256"] == RULE_HASH
    assert row["code_under_observation"]["rule_count"] == 68
    assert row["source"]["repository"] == "ASK92/lolbin-detection-system"
    assert row["source"]["pinned_commit"] == SOURCE_COMMIT
    assert row["source"]["evtx"]["path"] == "data/Sysmon_logs/SysmonLogs_20251113.evtx"
    assert row["source"]["evtx"]["git_blob_sha1"] == SOURCE_BLOB
    assert row["source"]["evtx"]["size_bytes"] == 66_129_920

    basis = row["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["breachscope_default_branch_search_hits_for_source_names"] == 0
    assert basis["evtx_bytes_downloaded_before_binding"] is False
    assert basis["evtx_binary_opened_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False


def test_p2_24c_uses_stricter_upstream_benign_time_boundary() -> None:
    row = _load()
    ground = row["source_ground_truth"]
    facts = "\n".join(ground["label_policy_supported_facts"])
    assert "2025-11-15 23:59:59" in facts
    assert "2025-11-16 22:00:00" in facts
    assert ground["strict_benign_cutoff_local"] == "2025-11-15T23:59:59"
    assert ground["boundary_resolution"].startswith("use the stricter")
    assert "final measurement eligibility requires every parsed event timestamp" in ground["evaluation_label_basis"]


def test_p2_24c_avoids_overlapping_later_exports() -> None:
    basis = _load()["selection_basis"]
    assert basis["single_earliest_raw_export_selected"] is True
    assert basis["later_overlapping_exports_excluded_to_reduce_snapshot_duplication_risk"] is True


def test_p2_24c_requires_contract_before_record_parse_or_detection() -> None:
    protocol = _load()["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["content_observation_before_phase_c_contract"] == "prohibited"
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert "timestamp" in protocol["phase_c_timestamp_fail_closed_rule"]
    assert "NOT_MEASURED" in protocol["phase_c_timestamp_fail_closed_rule"]


def test_p2_24c_claims_nothing_before_measurement() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_benign_evaluation"] == "NOT_YET_MEASURED"
    assert claim["benign_false_positive_rate"] == "NOT_YET_MEASURED"
    assert claim["source_label_eligibility"] == "PROVISIONAL_UNTIL_TIMESTAMP_CONTRACT_PASSES"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["representative_production_population"] == "NOT_CLAIMED"

