from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_14d_final_blind_scoring_contract.yaml"


def _load():
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_14d_freezes_exact_detector_and_input():
    data = _load()
    assert data["status"] == "SCORING_CONTRACT_FROZEN_BEFORE_DETECTION"
    assert data["frozen_detector"]["repo_commit"] == "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
    assert data["frozen_detector"]["rule_count"] == 66
    assert data["bound_input"]["archive_sha256"] == "99e0ca3dae2f7582d9757dfe41b4f1fb149b197fe3bb751613760087f2d68594"
    assert data["bound_input"]["evtx_file_count"] == 278
    assert data["bound_input"]["total_records"] == 37364
    assert data["bound_input"]["parsed_records"] == 37364
    assert data["bound_input"]["parse_errors"] == 0
    assert data["bound_input"]["file_open_errors"] == 0


def test_p2_14d_is_one_pass_and_fail_closed():
    data = _load()
    protocol = data["scoring_protocol"]
    assert protocol["run_frozen_detector_exactly_once"] is True
    assert protocol["run_all_66_rules"] is True
    assert protocol["denominator_records"] == 37364
    assert protocol["denominator_files"] == 278
    assert protocol["post_result_denominator_substitution_allowed"] is False
    assert protocol["fail_closed_on_archive_hash_mismatch"] is True
    assert protocol["fail_closed_on_path_manifest_hash_mismatch"] is True
    assert protocol["fail_closed_if_record_count_differs_from_inventory"] is True
    assert protocol["partial_run_can_be_canonical"] is False
    assert protocol["retry_after_successful_canonical_scoring_allowed"] is False


def test_p2_14d_preserves_claim_boundaries():
    data = _load()
    interpretation = data["interpretation_contract"]
    claims = data["claim_boundary"]
    attestations = data["attestations"]

    assert interpretation["finding_count_is_not_recall"] is True
    assert interpretation["flagged_event_fraction_is_not_false_positive_rate"] is True
    assert interpretation["source_attack_sample_membership_is_not_event_level_malicious_ground_truth"] is True
    assert interpretation["no_confusion_matrix_without_independent_event_level_ground_truth"] is True

    assert claims["production_accuracy"] == "NOT_CLAIMED"
    assert claims["production_precision"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["event_level_ground_truth"] == "NOT_AVAILABLE"

    assert attestations["detector_executed_during_p2_14d"] is False
    assert attestations["scoring_performed_during_p2_14d"] is False
    assert attestations["scoring_contract_frozen_before_detection"] is True
