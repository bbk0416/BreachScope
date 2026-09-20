from __future__ import annotations

import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_26c_gha_windows_benign_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_26c_gha_windows_benign_one_pass.py"

RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
RUNNER_HASH = "1edeca9e33e30286cc3b5bf31117c3004f42780d3924d0e7756bacf041053128"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_p2_26c_contract_binds_frozen_detector_and_canonical_phase_b_run() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_AFTER_IDENTITY_BEFORE_RECORD_PARSE"

    frozen = row["frozen_product"]
    assert frozen["repo_commit"] == "b70ab6bbc519ac137dae324ad860391371f470db"
    assert frozen["rules_tree_sha256"] == RULE_HASH
    assert frozen["rule_count"] == 68
    assert frozen["rule_file_count"] == 5

    observed = row["phase_b_identity_observation"]
    assert observed["binding_merge_commit"] == "6f431ba2cf2d0fc08aa8b2124f020ced93da404f"
    assert observed["workflow_run_id"] == 35492508210
    assert observed["workflow_run_attempt"] == 1
    assert observed["workflow_conclusion"] == "success"
    assert observed["repository_checkout_before_collection"] is False
    assert observed["repository_code_executed_before_collection"] is False
    assert observed["evtx_records_parsed"] is False
    assert observed["detector_executed"] is False


def test_p2_26c_contract_binds_exact_artifact_and_all_five_file_identities() -> None:
    row = _load()

    artifact = row["source_artifact"]
    assert artifact["artifact_id"] == 10599666432
    assert artifact["artifact_name"] == "p2-26c-benign-source-35492508210"
    assert artifact["artifact_size_bytes"] == 147091
    assert artifact["artifact_digest"] == (
        "sha256:cd733c028bacef530ed95ccc094a81cbe50f0c7386ba1ea107745a2730e0e719"
    )
    assert artifact["expired"] is False

    files = row["source_identity"]["files"]
    assert [(item["channel"], item["filename"], item["available"]) for item in files] == [
        ("Security", "Security.evtx", True),
        ("System", "System.evtx", True),
        ("Application", "Application.evtx", True),
        ("Windows PowerShell", "Windows_PowerShell.evtx", True),
        (
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell_Operational.evtx",
            True,
        ),
    ]
    assert [item["size_bytes"] for item in files] == [
        1_118_208,
        1_118_208,
        69_632,
        69_632,
        69_632,
    ]
    assert [item["sha256"] for item in files] == [
        "d07ecab6b9782c9196bf21548ff6fe8ce88311f939456ec66a05586dc2fe0806",
        "3a3afebd5319f6ef373a9dab97783cb37bea2012bcb820ec80c7e7f2d02da741",
        "8b0d5010af14d6b973a5421e1520da4141c0f662a1a7411408f539bb6ac32864",
        "f5f9e97a6b1ec8d46a9bd5b9d4ccae96521b85517b0337b248814d2e974a968b",
        "f5f9e97a6b1ec8d46a9bd5b9d4ccae96521b85517b0337b248814d2e974a968b",
    ]
    assert (
        row["source_identity"][
            "identical_sha_files_are_retained_as_separate_preregistered_channel_exports"
        ]
        is True
    )


def test_p2_26c_runner_hash_is_frozen_before_record_parse() -> None:
    row = _load()
    assert row["runner"]["sha256"] == RUNNER_HASH
    assert _text_sha256(RUNNER) == RUNNER_HASH
    assert row["runner"]["permanent_exclusive_lock"] is True


def test_p2_26c_scoring_is_bounded_event_fraction_not_production_fpr() -> None:
    scoring = _load()["scoring"]
    assert scoring["aggregate_formula"] == "unique_flagged_events / parsed_events"
    assert scoring["metric_name"] == "observed_source_intent_benign_flagged_event_fraction"
    assert scoring["all_68_rules_evaluated"] is True
    assert scoring["event_level_manual_adjudication"] is False
    assert scoring["parse_errors"] == "REPORTED_SEPARATELY"

    claim = _load()["claim_boundary"]
    assert claim["fresh_benign_revalidation"] == "NOT_YET_MEASURED"
    assert claim["observed_source_intent_benign_flagged_event_fraction"] == "NOT_YET_MEASURED"
    assert claim["event_level_benign_ground_truth"] == "NOT_AVAILABLE"
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["general_fresh_full_benign_fpr"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["representative_production_population"] == "NOT_CLAIMED"


def test_p2_26c_protocol_is_one_pass_fail_closed_and_no_rerun() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_must_merge_before_any_evtx_record_parse"] is True
    assert protocol["contract_must_merge_before_detector_execution"] is True
    assert protocol["artifact_identity_reverified_before_parse"] is True
    assert protocol["every_available_file_size_and_sha256_reverified_before_parse"] is True
    assert protocol["permanent_lock_acquired_before_source_verification_and_parse"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["product_or_rules_tuning_after_contract_before_result"] is False
    assert protocol["source_hash_or_size_mismatch_fails_closed"] is True
    assert protocol["phase_b_rerun_allowed"] is False
