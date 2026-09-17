import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_15b_remote_execution_post_change.yaml"
MEASUREMENT = (
    ROOT / "external_baseline" / "results" / "p2_15b_6e3a297" / "measurement.json"
)


def _load():
    evidence = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    result = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    return evidence, result


def test_p2_15b_is_explicitly_post_change_not_blind() -> None:
    evidence, _ = _load()
    assert evidence["analysis_class"] == "post_change_external_reconstruction_diagnostic"
    notes = evidence["protocol_notes"]
    assert notes["corpus_was_previously_observed"] is True
    assert notes["development_informed_by_prior_result"] is True
    assert notes["blind_evaluation"] is False
    assert notes["p2_14e_final_blind_holdout_rerun"] is False


def test_p2_15b_measurement_matches_merge_commit() -> None:
    evidence, result = _load()
    assert result["schema"] == evidence["measurement_evaluator_schema"]
    assert result["repo_commit"] == evidence["code_under_observation"]["repo_commit"]
    assert result["archive_sha256"] == evidence["source_binding"]["archive_sha256"]
    assert result["rules_tree_sha256"] == evidence["code_under_observation"]["rules_tree_sha256"]
    assert result["events"] == 196081
    assert result["parse_errors"] == 0
    assert result["rules"] == 66
    assert result["findings"] == 38
    assert result["flagged_events"] == 35
    assert result["chains"] == 233
    assert result["chain_types"] == {
        "activity": 5,
        "download_exec": 4,
        "remote_execution": 5,
        "session": 219,
    }
    assert result["cross_host_chains"] == 5
    assert result["scranton_nashua_chains"] == 5
    assert result["scenarios"] == 1
    assert result["cross_host_scenarios"] == 0
    assert result["scranton_nashua_scenarios"] == 0


def test_p2_15b_remote_chains_are_narrowly_recorded() -> None:
    evidence, result = _load()
    rows = [row for row in result["largest_chains"] if row["chain_type"] == "remote_execution"]
    assert len(rows) == 5
    assert sorted(row["event_count"] for row in rows) == [3, 4, 4, 4, 4]
    assert sorted(row["finding_count"] for row in rows) == [0, 2, 2, 2, 2]
    assert all(set(row["hosts"]) == {"SCRANTON", "NASHUA"} for row in rows)

    aligned = {row["plan_step"]: row for row in evidence["remote_execution_diagnostic_alignment"]}
    assert aligned["8.A"]["observed_chains"] == 1
    assert aligned["8.C"]["observed_chains"] == 4
    assert aligned["8.B"]["observed_chains"] == "NOT_ASSERTED"


def test_p2_15b_claim_boundary_remains_not_claimed() -> None:
    evidence, result = _load()
    boundary = evidence["claim_boundary"]
    for key in ("chain_precision", "chain_recall", "scenario_accuracy", "plan_step_coverage_rate"):
        assert boundary[key] == "NOT_CLAIMED"
    assert boundary["event_level_chain_ground_truth"] == "NOT_AVAILABLE"
    assert result["claim_boundary"]["chain_precision"] == "NOT_CLAIMED"
    assert result["claim_boundary"]["chain_recall"] == "NOT_CLAIMED"


def test_p2_15b_measurement_file_is_content_bound() -> None:
    import hashlib

    evidence, _ = _load()
    digest = hashlib.sha256(MEASUREMENT.read_bytes()).hexdigest()
    assert digest == evidence["measurement_sha256"]
