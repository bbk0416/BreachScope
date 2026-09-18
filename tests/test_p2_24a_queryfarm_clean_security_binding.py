from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_24a_queryfarm_clean_security_benign_binding.yaml"

MAIN = "35e20ad9a668552a87de567fdd491f1602c3930c"
RULE_HASH = "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
SOURCE_COMMIT = "add9265cbf1b2ecf225f91d2e883b270f34cd751"
EVTX_BLOB = "7c0eab77b0ed388da193827a14286a56634b3a6b"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_24a_binds_unused_clean_evtx_before_binary_observation() -> None:
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_benign_evtx_binding"
    assert row["code_under_observation"]["repo_commit"] == MAIN
    assert row["code_under_observation"]["rules_tree_sha256"] == RULE_HASH
    assert row["code_under_observation"]["rule_count"] == 68
    assert row["source"]["repository"] == "Query-farm/vgi-evtx"
    assert row["source"]["pinned_commit"] == SOURCE_COMMIT
    assert row["source"]["evtx"]["git_blob_sha1"] == EVTX_BLOB
    assert row["source"]["evtx"]["size_bytes"] == 69632

    basis = row["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["breachscope_default_branch_search_hits_for_source_names"] == 0
    assert basis["evtx_bytes_downloaded_before_binding"] is False
    assert basis["evtx_binary_opened_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False


def test_p2_24a_label_comes_only_from_explicit_upstream_clean_description() -> None:
    row = _load()
    ground = row["source_ground_truth"]
    assert ground["evaluation_label_basis"] == "benign_by_upstream_explicit_clean_fixture_description"
    facts = "\n".join(ground["documentation_supported_facts"])
    assert "clean Windows Security event log" in facts
    assert "7 records" in facts
    assert ground["event_level_manual_adjudication"] is False
    assert ground["known_attack_execution_in_fixture"] == "NOT_CLAIMED"
    assert row["source"]["upstream_provenance"]["same_git_blob_sha1"] == EVTX_BLOB


def test_p2_24a_requires_hash_binding_and_runner_before_any_record_parse() -> None:
    protocol = _load()["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["content_observation_before_phase_c_contract"] == "prohibited"
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["no_result_driven_remeasurement"] is True
    assert "SHA256" in protocol["phase_c_required_before_data_content_observation"]


def test_p2_24a_claim_boundary_discloses_tiny_fixture() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_benign_evaluation"] == "NOT_YET_MEASURED"
    assert claim["benign_false_positive_rate"] == "NOT_YET_MEASURED"
    assert claim["corpus_representativeness"] == "VERY_LIMITED_7_RECORD_FIXTURE"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["representative_production_population"] == "NOT_CLAIMED"

