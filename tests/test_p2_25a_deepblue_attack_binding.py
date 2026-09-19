from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_25a_deepblue_attack_binding.yaml"

RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
SOURCE_COMMIT = "2eecc65698e8666408ece67525577c895676d579"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_25a_binds_current_p2_24d_rulepack() -> None:
    row = _load()
    frozen = row["frozen_detector"]
    assert frozen["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert frozen["rule_change_commit"] == "66f5d2e0061ea34113038a712597113a6df7bd63"
    assert frozen["rules_tree_sha256"] == RULE_HASH
    assert frozen["rule_count"] == 68
    assert frozen["rule_file_count"] == 5
    assert frozen["fresh_attack_revalidation_before_binding"] == "NOT_RUN"
def test_p2_25a_binds_four_exact_deepblue_evtx_blobs() -> None:
    row = _load()
    assert row["source"]["repository"] == "sans-blue-team/DeepBlueCLI"
    assert row["source"]["pinned_commit"] == SOURCE_COMMIT
    datasets = {item["dataset_id"]: item for item in row["datasets"]}
    assert datasets["deepblue-mimikatz-lsadump-sam"] == {
        "dataset_id": "deepblue-mimikatz-lsadump-sam",
        "path": "evtx/mimikatz-privesc-hashdump.evtx",
        "git_blob_sha1": "f82f01d16bc8cae33d20f96d0ea31519c08e2989",
        "size_bytes": 69632,
        "source_label": "Mimikatz lsadump::sam",
    }
    assert datasets["deepblue-powershell-obfuscation-encoding"]["git_blob_sha1"] == (
        "015795a0164f24be5eb91ea539cf154b1bcc3e65"
    )
    assert datasets["deepblue-powershell-obfuscation-encoding"]["size_bytes"] == 1_118_208
    assert datasets["deepblue-metasploit-psexec-powershell-security"]["git_blob_sha1"] == (
        "033aebcc0bdda1d498f7443dfece4b849891cb73"
    )
    assert datasets["deepblue-new-user-security"]["git_blob_sha1"] == (
        "ae8553affd793e7b266972bf2b992daf0947cb13"
    )
def test_p2_25a_source_labels_are_readme_backed() -> None:
    facts = "\n".join(_load()["source"]["documentation"]["supported_facts"])
    assert "Mimikatz lsadump::sam" in facts
    assert "Obfuscation (encoding)" in facts
    assert "Metasploit PowerShell target (security)" in facts
    assert "New user creation" in facts


def test_p2_25a_is_pre_observation_and_one_pass() -> None:
    row = _load()
    basis = row["selection_basis"]
    assert basis["source_repository_previously_used_by_breachscope"] is False
    assert basis["breachscope_default_branch_search_hits_for_source_names"] == 0
    assert basis["evtx_payload_bytes_downloaded_before_binding"] is False
    assert basis["evtx_binary_opened_before_binding"] is False
    assert basis["evtx_records_parsed_before_binding"] is False
    assert basis["breachscope_detector_executed_before_binding"] is False

    protocol = row["protocol"]
    assert protocol["phase_a_binding_only"] is True
    assert protocol["detector_execution_before_phase_c_contract"] == "prohibited"
    assert protocol["content_observation_before_phase_c_contract"] == "prohibited"
    assert protocol["duplicate_measurement_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["no_result_driven_remeasurement"] is True
def test_p2_25a_claims_nothing_before_measurement() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_attack_revalidation_for_current_rulepack"] == "NOT_YET_MEASURED"
    assert claim["dataset_level_attack_detection"] == "NOT_YET_MEASURED"
    assert claim["event_level_recall"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
