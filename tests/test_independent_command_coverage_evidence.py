from pathlib import Path
import subprocess

import yaml

from breachscope.rules import load_rules
from scripts.evaluate_external_holdout import rules_tree_hash


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "external_baseline" / "independent_command_coverage_remediation.yaml"
CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"

OLD_HASH = "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
NEW_HASH = "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
DETECTOR_COMMIT = "bad0c88037d489f5b375c120002be74ac6082ffa"


def _yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_independent_command_remediation_records_exact_transition() -> None:
    record = _yaml(RECORD)
    remediation = record["remediation"]

    assert record["schema"] == "breachscope.independent_command_coverage_remediation.v1"
    assert record["analysis_id"] == "independent-command-coverage-remediation-v1"
    assert record["status"] == "IMPLEMENTED_POSTHOC_PENDING_FRESH_REVALIDATION"
    assert record["basis"]["brawl_canonical_result_modified"] is False
    assert record["basis"]["brawl_canonical_rerun"] is False
    assert record["basis"]["brawl_score_optimization_target"] is False

    assert remediation["detector_repo_commit"] == DETECTOR_COMMIT
    assert remediation["from_rules_tree_sha256"] == OLD_HASH
    assert remediation["to_rules_tree_sha256"] == NEW_HASH
    assert remediation["rule_count_before"] == 69
    assert remediation["rule_count_after"] == 73
    assert remediation["rule_file_count"] == 5
    assert remediation["modified_rule_ids"] == ["R-WMI-Create", "R-REG-RunKey"]
    assert remediation["added_rule_ids"] == [
        "R-NETWORK-CONFIG-NBTSTAT",
        "R-PERMISSION-GROUPS-LOCAL-NET",
        "R-PERMISSION-GROUPS-DOMAIN-NET",
        "R-SMB-ADMIN-SHARE-NET-USE",
    ]
    assert remediation["fresh_attack_revalidation"] == "NOT_RUN"
    assert remediation["fresh_benign_revalidation"] == "NOT_RUN"


def test_independent_command_remediation_matches_live_rule_tree() -> None:
    rule_hash, file_count = rules_tree_hash(ROOT / "rules")
    rules = load_rules(ROOT / "rules")

    assert rule_hash == NEW_HASH
    assert len(rules) == 73
    assert file_count == 5

    changed = {
        row["path"]: row["git_blob_sha1"]
        for row in _yaml(RECORD)["remediation"]["changed_rule_files"]
    }
    for path, expected_blob in changed.items():
        actual = subprocess.check_output(
            ["git", "rev-parse", f"{DETECTOR_COMMIT}:{path}"],
            cwd=ROOT,
            text=True,
        ).strip()
        assert actual == expected_blob


def test_current_chain_marks_73_rule_detector_pending_fresh_revalidation() -> None:
    chain = _yaml(CHAIN)

    assert (
        chain["current_evidence_id"]
        == "independent-command-coverage-remediation-current-detection-evidence"
    )
    assert chain["current_frozen_detector"] == {
        "repo_commit": DETECTOR_COMMIT,
        "rules_tree_sha256": NEW_HASH,
        "rule_count": 73,
        "rule_file_count": 5,
    }

    assert [row["remediation_id"] for row in chain["posthoc_remediations"]] == [
        "p2-24d-rule-noise-remediation",
        "p2-35i-original-filename-masquerading-remediation",
        "independent-command-coverage-remediation-v1",
    ]

    current = chain["current_rulepack_validation"]
    assert current == {
        "rule_change_id": "independent-command-coverage-remediation-v1",
        "current_revalidation_id": "NOT_RUN",
        "fresh_attack_revalidation_after_current_rule_change": "NOT_RUN",
        "fresh_benign_revalidation_after_current_rule_change": "NOT_RUN",
        "prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack": False,
        "prior_p2_35m_revalidation_applies_to_current_rulepack": False,
        "fresh_current_rulepack_performance_available": False,
    }


def test_p2_35m_remains_historical_and_claims_stay_bounded() -> None:
    chain = _yaml(CHAIN)
    p35m = chain["post_remediation_revalidations"][-1]

    assert p35m["revalidation_id"] == "p2-35m-current-rulepack-fresh-source-revalidation"
    assert p35m["detector_rules_tree_sha256"] == OLD_HASH
    assert p35m["detector_rules_tree_sha256"] != chain["current_frozen_detector"]["rules_tree_sha256"]
    assert p35m["fixture_count"] == 10
    assert p35m["hits"] == 6
    assert p35m["expected_technique_matches"] == 1
    assert p35m["benign_parsed_events"] == 425974
    assert p35m["benign_flagged_events"] == 4

    claims = chain["claim_boundary"]
    assert claims["production_accuracy"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"


def test_development_recheck_is_explicitly_non_fresh() -> None:
    record = _yaml(RECORD)
    development = record["development_validation"]

    assert development["independent_synthetic_tests"] == {
        "status": "PASS",
        "passed": 10,
        "failed": 0,
        "test_file": "tests/test_independent_command_gap_remediation.py",
    }
    assert development["related_regression"]["status"] == "PASS"
    assert development["related_regression"]["passed"] == 47
    assert development["related_regression"]["failed"] == 0
    assert development["full_regression"] == {
        "status": "PASS",
        "passed": 1321,
        "failed": 0,
    }
    assert development["project_readiness"] == {
        "status": "PASS",
        "score": 100,
        "max_score": 100,
        "checks_passed": 16,
        "warnings": 0,
        "failures": 0,
    }
    assert development["quality_gate"] == {
        "status": "PASS",
        "score": 100,
        "max_score": 100,
        "checks_passed": 6,
        "warnings": 0,
        "failures": 0,
    }
    verifier = development["current_evidence_verifier"]
    assert verifier["status"] == "PASS"
    assert verifier["schema"] == "breachscope.current_detection_evidence_verification.v13"
    assert verifier["current_rules_tree_sha256"] == NEW_HASH
    assert verifier["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert verifier["fresh_benign_revalidation_after_current_rule_change"] == "NOT_RUN"

    brawl = development["brawl_posthoc_development_recheck"]
    assert brawl["class"] == "POSTHOC_DEVELOPMENT_ONLY_NOT_FRESH_VALIDATION"
    assert brawl["rules_frozen_before_recheck"] is True
    assert brawl["source_already_observed"] is True
    assert brawl["canonical_result_recomputed"] is False
    assert brawl["canonical_result_replaced"] is False
    assert brawl["post_pair_diagnostic"] == {
        "frozen_pair_count": 133,
        "would_meet_frozen_hit_dimensions": 1,
        "expected_technique_same_host_outside_window": 23,
        "telemetry_present_no_expected_technique_finding": 100,
        "no_normalized_telemetry_in_frozen_window": 9,
    }

    boundaries = record["claim_boundary"]
    assert boundaries["fresh_validation"] is False
    assert boundaries["prior_p2_35m_revalidation_applies_to_current_rulepack"] is False
    assert boundaries["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundaries["production_accuracy"] == "NOT_CLAIMED"