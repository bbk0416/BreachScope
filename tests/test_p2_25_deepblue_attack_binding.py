from __future__ import annotations
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_25_deepblue_attack_binding.yaml"
RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"

def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))

def test_p2_25_binds_fresh_deepblue_source_before_observation() -> None:
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_attack_fixture_binding"
    assert row["code_under_observation"]["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert row["code_under_observation"]["rules_tree_sha256"] == RULE_HASH
    assert row["code_under_observation"]["rule_count"] == 68
    assert row["source"]["repository"] == "sans-blue-team/DeepBlueCLI"
    assert row["source"]["pinned_commit"] == "2eecc65698e8666408ece67525577c895676d579"
    assert row["source"]["license"] == "GPL-3.0"
    basis = row["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["breachscope_default_branch_search_hits_for_source_names"] == 0
    assert basis["evtx_bytes_downloaded_before_binding"] is False
    assert basis["evtx_binaries_opened_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False

def test_p2_25_binds_eight_readme_labeled_attack_fixtures() -> None:
    row = _load()
    datasets = row["source"]["datasets"]
    assert len(datasets) == 8
    assert len({d["dataset_id"] for d in datasets}) == 8
    assert len({d["path"] for d in datasets}) == 8
    assert all(d["path"].endswith(".evtx") for d in datasets)
    assert all(d["size_bytes"] > 0 for d in datasets)
    assert all(len(d["git_blob_sha1"]) == 40 for d in datasets)
    labels = {d["scenario_label"] for d in datasets}
    assert labels == {"Obfuscation (encoding)","Metasploit PowerShell target (security)","Mimikatz lsadump::sam","Password spraying","PowerSploit (security)","PSAttack","New user creation","Event log manipulation"}
    ground = row["source_ground_truth"]
    assert ground["fixture_count"] == 8
    assert ground["event_level_labels"] == "NOT_AVAILABLE"
    assert ground["attck_technique_labels"] == "NOT_ASSIGNED_BY_BINDING"
    assert ground["known_attack_fixture_intent"] == "SUPPORTED_BY_UPSTREAM_README"

def test_p2_25_requires_hash_contract_before_content_observation() -> None:
    protocol = _load()["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["content_observation_before_phase_c_contract"] == "prohibited"
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["no_result_driven_remeasurement"] is True
    assert "SHA256" in protocol["phase_c_required_before_data_content_observation"]

def test_p2_25_scoring_is_fixture_hit_rate_not_recall() -> None:
    scoring = _load()["planned_scoring"]
    assert scoring["unit"] == "fixture"
    assert scoring["fixture_hit_definition"] == "one or more findings on a source-labeled attack fixture"
    assert scoring["aggregate"] == "fixture_hits / 8"
    assert scoring["event_level_recall"] == "NOT_MEASURED"
    assert scoring["technique_recall"] == "NOT_MEASURED"
    assert scoring["production_detection_rate"] == "NOT_CLAIMED"
    claim = _load()["claim_boundary"]
    assert claim["fresh_attack_revalidation"] == "NOT_YET_MEASURED"
    assert claim["event_level_recall"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
