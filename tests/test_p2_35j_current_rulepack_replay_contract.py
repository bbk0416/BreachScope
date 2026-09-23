from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35j_current_rulepack_replay_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35j_current_rulepack_replay.py"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35j_runner", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p2_35j_freezes_current_69_rule_product() -> None:
    row = _load()
    frozen = row["frozen_product"]
    assert frozen["repo_commit"] == "2401f8b9b6a569b8b932451f0a0ae20ffa26abbc"
    assert frozen["rules_tree_sha256"] == (
        "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    )
    assert frozen["rule_count"] == 69
    assert frozen["rule_file_count"] == 5


def test_p2_35j_runner_is_byte_frozen_and_analysis_id_global_locked() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-35j-current-rulepack-postchange-replay-v1"
    assert row["runner"]["sha256"] == _sha(RUNNER)
    assert row["runner"]["sha256"] == (
        "4c797021b9cd035277ab355914d1826709a6b71be491922e440c95a7a6046ca0"
    )
    module = _module()
    assert module.ANALYSIS_ID == row["analysis_id"]
    assert module.global_lock_path().name == "P2_35J_CURRENT_RULEPACK_REPLAY.lock"


def test_p2_35j_global_lock_blocks_second_acquisition(tmp_path: Path) -> None:
    module = _module()
    lock = tmp_path / "lock"
    module.acquire_global_lock(lock)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    assert payload["analysis_id"] == "p2-35j-current-rulepack-postchange-replay-v1"
    with pytest.raises(RuntimeError, match="already permanently locked"):
        module.acquire_global_lock(lock)


def test_p2_35j_reuses_exact_p2_25_attack_identities() -> None:
    row = _load()
    attack = row["attack_replay"]
    assert attack["fresh_external_source"] is False
    assert attack["pinned_commit"] == "2eecc65698e8666408ece67525577c895676d579"
    assert len(attack["datasets"]) == 8
    assert [x["dataset_id"] for x in attack["datasets"]] == [
        "obfuscation-encoding",
        "metasploit-psexec-powershell-security",
        "mimikatz-lsadump-sam",
        "password-spray",
        "powersploit-security",
        "psattack-security",
        "new-user-security",
        "eventlog-manipulation",
    ]
    assert all(len(x["sha256"]) == 64 for x in attack["datasets"])


def test_p2_35j_reuses_exact_p2_26c_benign_artifact_identity() -> None:
    row = _load()
    benign = row["benign_replay"]
    assert benign["fresh_external_source"] is False
    assert benign["workflow_run_id"] == 35492508210
    assert benign["artifact_id"] == 10599666432
    assert benign["artifact_name"] == "p2-26c-benign-source-35492508210"
    assert len([x for x in benign["files"] if x["available"]]) == 5
    assert {x["filename"] for x in benign["files"] if x["available"]} == {
        "Security.evtx",
        "System.evtx",
        "Application.evtx",
        "Windows_PowerShell.evtx",
        "Microsoft-Windows-PowerShell_Operational.evtx",
    }


def test_p2_35j_protocol_and_claim_boundary_fail_closed() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol[
        "contract_must_merge_before_current_detector_execution_on_replay_sources"
    ] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["replay_result_can_satisfy_fresh_external_validation_requirement"] is False
    claim = row["claim_boundary"]
    assert claim["fresh_external_source"] is False
    assert claim["independent_holdout"] is False
    assert claim["fresh_current_rulepack_performance"] == "NOT_CLAIMED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
