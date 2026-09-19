from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_25_deepblue_attack_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_25_deepblue_attack_one_pass.py"

RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
RUNNER_HASH = "1b5a5e60c47bcb36a0a07f063d4e558dea9f0c4e4de44d306ee73f977c61b024"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()

def test_p2_25_contract_binds_frozen_p2_24d_detector() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_BEFORE_EVTX_CONTENT_OBSERVATION"
    frozen = row["frozen_product"]
    assert frozen["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert frozen["rules_tree_sha256"] == RULE_HASH
    assert frozen["rule_count"] == 68
    assert frozen["rule_file_count"] == 5
    assert frozen["parent_remediation"] == "p2-24d-rule-noise-remediation"


def test_p2_25_contract_binds_all_eight_exact_sha256_values() -> None:
    row = _load()
    datasets = row["datasets"]
    assert len(datasets) == 8
    assert {d["dataset_id"] for d in datasets} == {
        "obfuscation-encoding",
        "metasploit-psexec-powershell-security",
        "mimikatz-lsadump-sam",
        "password-spray",
        "powersploit-security",
        "psattack-security",
        "new-user-security",
        "eventlog-manipulation",
    }
    assert {d["sha256"] for d in datasets} == {
        "b1d7c3411053a4190c93657265679958228b4bdb97652984c1564a67fcfab167",
        "84a086d6d4afc2a0de2040518757ee99eb83550156b95719c936a16130c7e9fb",
        "ee2278c513a42eb58b896e3696fabb5b2ee84c7a12cfc323993b1dbd74c75f3b",
        "de910e6c86476db2898d8b5f22201c7505a52c90d6a3b03f9362eebe8f242029",
        "b9d805537ca768fcbed1ed765e61bee56e16d3c1baec65b12567e73d865fb8ae",
        "2207cef54b911475c03ee268125b6290beedddae86bbd59ebca700cbb293f7c7",
        "6f9fe51d0a5dec63dc68f819e23bc14da5db0b75db4a68dfdf6b39f02868a379",
        "7645e96c6d778f96d60ce2a6f209cc4202385c9d87cc077139921270a8e9bb23",
    }
    observed = row["phase_b_identity_observation"]
    assert observed["performed_after_binding_merge"] is True
    assert observed["binding_merge_commit"] == "76ed109371daed7911c5ee8464196f3c77c278c4"
    assert observed["evtx_records_parsed"] is False
    assert observed["detector_executed"] is False
    assert observed["all_eight_size_and_git_blob_identities_verified"] is True


def test_p2_25_runner_hash_is_frozen() -> None:
    row = _load()
    assert row["runner"]["sha256"] == RUNNER_HASH
    assert _text_sha256(RUNNER) == RUNNER_HASH
    assert row["runner"]["permanent_exclusive_lock"] is True

def test_p2_25_scoring_is_fixture_level_only() -> None:
    scoring = _load()["scoring"]
    assert scoring["fixture_count"] == 8
    assert scoring["fixture_hit_definition"] == (
        "one or more detector findings after at least one event parses"
    )
    assert scoring["aggregate_formula"] == "fixture_hits / 8"
    assert scoring["event_level_recall"] == "NOT_MEASURED"
    assert scoring["technique_recall"] == "NOT_MEASURED"
    assert "reported" in scoring["parse_errors"]


def test_p2_25_protocol_is_one_pass_and_fail_closed() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_must_merge_before_any_evtx_record_parse"] is True
    assert protocol["contract_must_merge_before_detector_execution"] is True
    assert protocol["all_source_identities_reverified_before_first_record_parse"] is True
    assert protocol["permanent_lock_acquired_before_source_verification_and_parse"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["product_or_rules_tuning_after_contract_before_result"] is False
    assert protocol["source_hash_or_size_mismatch_fails_closed"] is True


def test_p2_25_claim_boundaries_remain_explicit() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_attack_revalidation"] == "NOT_YET_MEASURED"
    assert claim["fixture_hit_rate"] == "NOT_YET_MEASURED"
    assert claim["event_level_ground_truth"] == "NOT_AVAILABLE"
    assert claim["event_level_recall"] == "NOT_CLAIMED"
    assert claim["technique_recall"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
