import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_15c_remote_scenario_post_change.yaml"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_15c_0f5d6e2" / "measurement.json"


def _load():
    evidence = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    result = json.loads(MEASUREMENT.read_text(encoding="utf-8"))
    return evidence, result


def test_p2_15c_is_explicitly_post_change_not_blind() -> None:
    evidence, _ = _load()
    assert evidence["analysis_class"] == "post_change_external_scenario_diagnostic"
    notes = evidence["protocol_notes"]
    assert notes["corpus_was_previously_observed"] is True
    assert notes["development_informed_by_prior_result"] is True
    assert notes["blind_evaluation"] is False
    assert notes["p2_14e_final_blind_holdout_rerun"] is False
    assert notes["p2_14e_artifacts_modified"] is False


def test_p2_15c_measurement_matches_merge_commit() -> None:
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
    assert result["chain_types"] == {"activity": 5, "download_exec": 4, "remote_execution": 5, "session": 219}
    assert result["cross_host_chains"] == 5
    assert result["scranton_nashua_chains"] == 5
    assert result["scenarios"] == 2
    assert result["cross_host_scenarios"] == 1
    assert result["scranton_nashua_scenarios"] == 1


def test_p2_15c_remote_scenario_is_narrowly_recorded() -> None:
    evidence, result = _load()
    lateral = [row for row in result["scenario_rows"] if row["attack_stage"] == "lateral_movement"]
    assert len(lateral) == 1
    row = lateral[0]
    assert row["scenario_id"].startswith("scenario_remote_execution_")
    assert row["confidence"] == 0.9
    assert row["mitre_techniques"] == ["T1569.002"]
    assert row["chain_count"] == 4
    assert set(row["hosts"]) == {"SCRANTON", "NASHUA"}
    diagnostic = evidence["remote_scenario_diagnostic"]
    assert diagnostic["promoted_episode"]["method"] == "psexec"
    assert diagnostic["promoted_episode"]["chain_count"] == 4
    assert diagnostic["winrm_8a"]["remote_execution_chains"] == 1
    assert diagnostic["winrm_8a"]["scenario_promoted"] is False
    assert diagnostic["remote_file_staging_8b"]["scenario_alignment"] == "NOT_ASSERTED"


def test_p2_15c_promotion_contract_is_conservative() -> None:
    evidence, _ = _load()
    contract = evidence["promotion_contract"]
    assert contract["requires_explicit_source_target_metadata"] is True
    assert contract["requires_exactly_two_endpoint_hosts"] is True
    assert contract["requires_bilateral_findings"] is True
    assert contract["minimum_severity"] == "high"
    assert contract["method_technique_mapping"] == {"psexec": ["T1569.002"], "powershell": ["T1021.006"]}
    assert contract["episode_gap_seconds"] == 300
    assert contract["direction_sensitive"] is True
    assert contract["technique_sensitive"] is True


def test_p2_15c_claim_boundary_remains_not_claimed() -> None:
    evidence, result = _load()
    boundary = evidence["claim_boundary"]
    for key in ("chain_precision", "chain_recall", "scenario_precision", "scenario_recall", "scenario_accuracy", "plan_step_coverage_rate"):
        assert boundary[key] == "NOT_CLAIMED"
    assert boundary["event_level_chain_ground_truth"] == "NOT_AVAILABLE"
    assert result["claim_boundary"]["scenario_accuracy"] == "NOT_CLAIMED"
    assert result["claim_boundary"]["chain_precision"] == "NOT_CLAIMED"


def test_p2_15c_measurement_file_is_content_bound() -> None:
    evidence, _ = _load()
    assert hashlib.sha256(MEASUREMENT.read_bytes()).hexdigest() == evidence["measurement_sha256"]
