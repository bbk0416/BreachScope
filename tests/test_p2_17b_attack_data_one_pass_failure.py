from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_17b_attack_data_one_pass_failure.yaml"

def load():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))

def test_p2_17b_first_actual_run_is_sealed_as_operational_failure():
    row = load()
    run = row["first_actual_run"]
    assert run["status"] == "OPERATIONAL_FAILURE"
    assert run["completed_dataset_results"] == 0
    assert run["aggregate_path_label_hit_rate"] == "NOT_AVAILABLE"
    assert run["first_dataset"]["correlation"]["chains"] == 43
    assert run["first_dataset"]["scenario_stage_completed"] is False
    assert run["failure"]["cause"] == "UNDETERMINED"

def test_p2_17b_duplicate_run_is_not_evidence():
    duplicate = load()["concurrent_duplicate_run"]
    assert duplicate["began_after_first_run_failure"] is True
    assert duplicate["canonical_result_eligible"] is False
    assert duplicate["action"] == "terminated_without_using_output"
def test_p2_17b_corpus_cannot_be_rerun_for_canonical_score():
    row = load()
    protocol = row["protocol"]
    assert protocol["successful_one_pass_measurement_completed"] is False
    assert protocol["same_corpus_rerun_for_canonical_score_allowed"] is False
    assert protocol["duplicate_run_output_accepted"] is False
    assert row["claim_boundary"]["path_label_dataset_hit_rate"] == "NOT_AVAILABLE"
    assert row["claim_boundary"]["production_quality"] == "NOT_CLAIMED"
