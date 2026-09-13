from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "external_baseline" / "p2_14a_final_blind_holdout_preregistration.yaml"


def test_p2_14a_preregistration_freezes_selection_and_claim_boundaries():
    data = yaml.safe_load(RECORD.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.p2_14a_final_blind_holdout_preregistration.v1"
    assert data["status"] == "PREREGISTERED_BEFORE_CORPUS_SELECTION"
    assert data["frozen_detector"] == {
        "repo_commit": "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb",
        "rules_tree_sha256": "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92",
        "rule_count": 66,
        "rule_file_count": 4,
    }

    selection = data["selection_contract"]
    assert selection["corpus_must_not_be_from_otrf_security_datasets"] is True
    assert selection["corpus_must_not_be_from_nextronsystems_evtx_baseline"] is True
    assert selection["corpus_must_not_have_been_used_in_p2_09_through_p2_13"] is True
    assert selection["detector_outcomes_must_not_be_inspected_before_selection_is_frozen"] is True
    assert selection["no_detector_or_rule_changes_after_selection"] is True
    assert selection["no_post_result_denominator_substitution"] is True

    execution = data["execution_contract"]
    assert execution["step_order"] == [
        "select_one_eligible_corpus_without_scoring",
        "bind_source_revision_asset_identity_size_and_sha256",
        "inventory_and_parse_without_detector_scoring",
        "freeze_exact_scoring_contract",
        "run_frozen_66_rule_detector_once",
        "aggregate_once",
        "record_results_without_detector_tuning",
    ]
    assert execution["failed_or_partial_runs_cannot_be_promoted_to_canonical_results"] is True

    claims = data["claim_contract"]
    for key in (
        "production_accuracy",
        "production_detection_rate",
        "production_precision",
        "production_recall",
        "production_false_positive_rate",
        "representative_production_population",
    ):
        assert claims[key] == "NOT_CLAIMED"
    assert claims["event_level_ground_truth"] == "NOT_ASSUMED"

    assert data["forbidden_actions_before_p2_14a_merge"] == [
        "select_final_corpus",
        "download_final_corpus_for_detector_scoring",
        "inspect_detector_findings_on_candidate_corpora",
        "tune_rules_or_detector_for_candidate_corpora",
    ]
