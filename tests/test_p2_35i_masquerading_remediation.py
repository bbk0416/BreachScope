from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "external_baseline" / "p2_35i_masquerading_remediation.yaml"
CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"

OLD_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
NEW_HASH = "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
P35I_COMMIT = "d53861ea1dca4a5cf2ed57e7d147ab04b244e7f4"


def _record() -> dict:
    return yaml.safe_load(RECORD.read_text(encoding="utf-8"))


def test_p2_35i_remediation_records_exact_rule_transition() -> None:
    row = _record()
    remediation = row["remediation"]
    assert row["status"] == "IMPLEMENTED_POSTHOC_PENDING_FRESH_REVALIDATION"
    assert remediation["detector_repo_commit"] == P35I_COMMIT
    assert remediation["from_rules_tree_sha256"] == OLD_HASH
    assert remediation["to_rules_tree_sha256"] == NEW_HASH
    assert remediation["rule_count_before"] == 68
    assert remediation["rule_count_after"] == 69
    assert remediation["rule_file_count"] == 5
    assert remediation["added_rule_id"] == "R-MASQUERADE-ORIGINAL-NAME-MISMATCH"
    assert remediation["fresh_attack_revalidation"] == "NOT_RUN"
    assert remediation["fresh_benign_revalidation"] == "NOT_RUN"

    validation = row["local_validation"]
    assert validation["implementation_targeted_tests"] == {"passed": 33, "failed": 0}
    assert validation["evidence_chain_targeted_tests"] == {"passed": 62, "failed": 0}
    assert validation["full_regression"]["status"] == "PASS"
    assert validation["full_regression"]["passed"] == 1210
    assert validation["full_regression"]["failed"] == 0
    assert validation["quality_gate"]["status"] == "PASS"
    assert validation["quality_gate"]["score"] == 100
    assert validation["current_evidence_verifier"] == {
        "status": "PASS",
        "schema": "breachscope.current_detection_evidence_verification.v11",
    }


def test_p2_35i_win10_implementation_recheck_is_exact_and_zero_hit() -> None:
    check = _record()["development_rechecks"]["nextron_win10"]["implementation_recheck"]
    assert check["method"] == "8-shard raw-parent prefilter followed by exact XML predicate"
    assert check["sysmon_records_covered_exactly_once"] == 732_200
    assert check["chunk_range_covered"] == "0:11894"
    assert check["raw_parent_records"] == 5_861
    assert check["event1_parent_candidates"] == 17
    assert check["basename_mismatch_parent_candidates"] == 0
    assert check["refined_predicate_hits"] == 0


def test_p2_35i_development_rechecks_do_not_claim_accuracy() -> None:
    row = _record()
    assert row["development_rechecks"]["socbed"]["candidate_findings_on_exact_event"] == 1
    assert row["development_rechecks"]["atomic_evtx_t1036"]["refined_predicate_hits"] == 9
    assert row["development_rechecks"]["combined_nextron"]["sysmon_event1"] == 4_472
    assert row["development_rechecks"]["combined_nextron"]["refined_predicate_hits"] == 0
    assert row["development_rechecks"]["combined_nextron"]["confirmed_true_negatives"] == "NOT_CLAIMED"
    claims = row["claim_boundary"]
    assert claims["fresh_validation"] is False
    assert claims["prior_p2_25_attack_revalidation_applies_to_current_rulepack"] is False
    assert claims["prior_p2_26c_benign_revalidation_applies_to_current_rulepack"] is False
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["production_accuracy"] == "NOT_CLAIMED"


def test_p2_35i_current_chain_marks_prior_revalidations_non_current() -> None:
    chain = yaml.safe_load(CHAIN.read_text(encoding="utf-8"))
    assert chain["current_evidence_id"] == "p2-35m-current-rulepack-fresh-source-revalidation-current-detection-evidence"
    assert chain["current_frozen_detector"] == {
        "repo_commit": P35I_COMMIT,
        "rules_tree_sha256": NEW_HASH,
        "rule_count": 69,
        "rule_file_count": 5,
    }
    assert [row["remediation_id"] for row in chain["posthoc_remediations"]] == [
        "p2-24d-rule-noise-remediation",
        "p2-35i-original-filename-masquerading-remediation",
    ]
    current = chain["current_rulepack_validation"]
    assert current["current_revalidation_id"] == "p2-35m-current-rulepack-fresh-source-revalidation"
    assert current["fresh_attack_revalidation_after_current_rule_change"] == "COMPLETED"
    assert current["fresh_benign_revalidation_after_current_rule_change"] == "COMPLETED"
    assert current["prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack"] is False
    assert current["fresh_current_rulepack_performance_available"] is True
