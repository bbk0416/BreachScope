from __future__ import annotations

import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DIAGNOSIS = ROOT / "external_baseline" / "p2_27_schtask_4698_posthoc_diagnosis.yaml"
CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"
RULES = ROOT / "rules" / "p2_10_event_rules.yml"
P2_26C_RAW = ROOT / "external_baseline" / "results" / "p2_26c_81b839d" / "result.json"

RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
P2_26C_SHA = "9cff2b8616632031807dffa4771eb69e37f1040ef28576b9bd73442bbeb3264c"


def _load() -> dict:
    return yaml.safe_load(DIAGNOSIS.read_text(encoding="utf-8"))


def test_p2_27_is_evidence_only_and_preserves_canonical_p2_26c() -> None:
    row = _load()
    assert row["schema"] == "breachscope.p2_27_schtask_4698_posthoc_diagnosis.v1"
    assert row["review_class"] == "evidence_only_no_rule_change"

    parent = row["parent_evidence"]
    assert parent["current_evidence_id"] == (
        "p2-26c-fresh-benign-revalidation-current-detection-evidence"
    )
    assert parent["measurement_stored_sha256"] == P2_26C_SHA
    assert hashlib.sha256(P2_26C_RAW.read_bytes()).hexdigest() == P2_26C_SHA
    assert parent["detector_rules_tree_sha256"] == RULE_HASH
    assert parent["parsed_events"] == 1643
    assert parent["parse_errors"] == 0
    assert parent["findings"] == 1
    assert parent["flagged_events"] == 1
    assert parent["confirmed_false_positives"] == "NOT_CLAIMED"


def test_p2_27_records_exact_benign_consistent_flagged_event() -> None:
    event = _load()["p2_26c_flagged_event"]
    assert event["interpretation"] == "BENIGN_CONSISTENT_NOT_CONFIRMED_FALSE_POSITIVE"
    assert event["source_file_sha256"] == (
        "d07ecab6b9782c9196bf21548ff6fe8ce88311f939456ec66a05586dc2fe0806"
    )
    assert event["provider"] == "Microsoft-Windows-Security-Auditing"
    assert event["event_id"] == "4698"
    assert event["event_record_id"] == "398628"
    assert event["subject_user_name"] == "runneradmin"
    assert event["task_name"] == r"\HostedComputeAgent"
    assert event["task_principal_user"] == "runneradmin"
    assert event["task_hidden"] is False
    assert event["task_trigger_shape"] == "EMPTY"
    assert event["task_command"] == (
        r"C:\ProgramData\GitHub\HostedComputeAgent\hosted-compute-agent"
    )
    assert event["context"]["repository_checkout_before_collection"] is False
    assert event["context"]["repository_code_executed_before_collection"] is False


def test_p2_27_historical_attack_comparator_is_exact_and_materially_different() -> None:
    comparator = _load()["historical_attack_comparator"]
    source = comparator["source"]
    assert source["repository"] == "sbousseaden/EVTX-ATTACK-SAMPLES"
    assert source["commit"] == "4ceed2f4706daf601c212a8f91c113dd85349a2c"
    assert source["upstream_path"] == "Execution/temp_scheduled_task_4698_4699.evtx"
    assert source["git_blob_sha1"] == "9fc179fe1ac4a07733ef956f7b66046ddac362be"
    assert source["size_bytes"] == 69632
    assert source["sha256"] == (
        "a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70"
    )

    event = comparator["event"]
    assert event["event_id"] == "4698"
    assert event["task_name"] == r"\CYAlyNSS"
    assert event["task_hidden"] is True
    assert event["task_principal_user"] == "S-1-5-18"
    assert event["task_command"] == "cmd.exe"
    assert event["task_trigger_shape"] == "DAILY_CALENDAR_TRIGGER"
    assert comparator["comparison"]["both_match_current_event_only_rule"] is True
    assert comparator["comparison"]["task_semantics_differ_materially"] is True


def test_p2_27_current_rule_is_still_generic_low_severity_4698_telemetry() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    row = next(item for item in rules if item["id"] == "R-SCHTASK-4698")
    assert row == {
        "id": "R-SCHTASK-4698",
        "name": "Scheduled Task Creation Event",
        "description": "Windows Security 4698 scheduled task creation event",
        "field": "event_id",
        "operator": "equals",
        "pattern": "4698",
        "severity": "low",
        "mitre_technique": "T1053.005",
        "all_of": [
            {
                "field": "source",
                "operator": "equals",
                "pattern": "Microsoft-Windows-Security-Auditing",
            }
        ],
    }


def test_p2_27_rejects_overfit_refinements_and_closes_without_rule_change() -> None:
    row = _load()
    reviews = row["candidate_refinements_reviewed"]
    assert [item["candidate"] for item in reviews] == [
        "require TaskContent Hidden=true",
        "require TaskContent command=cmd.exe",
        "exclude exact HostedComputeAgent task name or executable path",
    ]
    assert {item["disposition"] for item in reviews} == {"REJECT_NO_CHANGE"}

    decision = row["decision"]
    assert decision["status"] == "CLOSE_POSTHOC_NO_CHANGE"
    assert decision["new_rule_added"] is False
    assert decision["existing_rule_modified"] is False
    assert decision["rule_tree_changed"] is False
    assert decision["detector_rerun_required"] is False
    assert decision["p2_26c_canonical_result_modified"] is False
    assert decision["current_detection_evidence_rewrite_required"] is False


def test_p2_27_does_not_rewrite_current_detection_chain_or_claim_fpr() -> None:
    diagnosis = _load()
    chain = yaml.safe_load(CHAIN.read_text(encoding="utf-8"))

    assert chain["current_evidence_id"] == (
        "independent-command-coverage-remediation-current-detection-evidence"
    )
    assert chain["current_frozen_detector"]["rules_tree_sha256"] == (
        "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
    )
    assert [row["remediation_id"] for row in chain["posthoc_remediations"]] == [
        "p2-24d-rule-noise-remediation",
        "p2-35i-original-filename-masquerading-remediation",
        "independent-command-coverage-remediation-v1",
    ]
    assert [row["revalidation_id"] for row in chain["post_remediation_revalidations"]] == [
        "p2-25-deepbluecli-fresh-attack",
        "p2-26c-gha-windows-fresh-benign",
        "p2-35m-current-rulepack-fresh-source-revalidation",
    ]

    boundary = diagnosis["claim_boundary"]
    assert boundary["review_is_fresh_evaluation"] is False
    assert boundary["parent_p2_26c_is_modified"] is False
    assert boundary["parent_p2_26c_may_be_used_as_development_data_after_this_review"] is True
    assert boundary["event_level_benign_ground_truth"] == "NOT_AVAILABLE"
    assert boundary["benign_consistent_event_is_confirmed_false_positive"] is False
    assert boundary["confirmed_false_positives"] == "NOT_CLAIMED"
    assert boundary["general_fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
