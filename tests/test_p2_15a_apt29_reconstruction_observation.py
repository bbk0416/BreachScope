import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_15a_apt29_reconstruction_observation.yaml"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_15a_5ca21b19" / "measurement.json"


def test_p2_15a_claim_boundary_is_narrow() -> None:
    evidence = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))

    assert evidence["analysis_class"] == "post_hoc_external_reconstruction_diagnostic"
    boundary = evidence["claim_boundary"]
    assert boundary["event_level_chain_ground_truth"] == "NOT_AVAILABLE"
    assert boundary["chain_precision"] == "NOT_CLAIMED"
    assert boundary["chain_recall"] == "NOT_CLAIMED"
    assert boundary["scenario_accuracy"] == "NOT_CLAIMED"
    assert boundary["production_reconstruction_quality"] == "NOT_CLAIMED"
    assert evidence["protocol_notes"]["blind_evaluation"] is False
    assert evidence["protocol_notes"]["p2_14e_final_blind_holdout_rerun"] is False


def test_p2_15a_external_plan_has_scranton_to_nashua_steps() -> None:
    evidence = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    steps = evidence["plan_structure"]["corpus_internal_cross_host_steps"]
    assert [row["step"] for row in steps] == ["8.A", "8.B", "8.C"]
    assert {(row["source"], row["target"]) for row in steps} == {("SCRANTON", "NASHUA")}
    assert evidence["plan_structure"]["attack_action_rows"] == 26


def test_p2_15a_measurement_matches_recorded_observation() -> None:
    evidence = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    result = json.loads(MEASUREMENT.read_text(encoding="utf-8"))

    assert result["schema"] == "breachscope.p2_15a_external_reconstruction_observation.v1"
    assert result["analysis_class"] == "post_hoc_external_reconstruction_diagnostic"
    assert result["repo_commit"] == evidence["code_under_observation"]["repo_commit"]
    assert result["archive_sha256"] == evidence["source_binding"]["archive_sha256"]
    assert result["rules_tree_sha256"] == evidence["code_under_observation"]["rules_tree_sha256"]
    assert result["events"] == 196081
    assert result["parse_errors"] == 0
    assert result["rules"] == 66
    assert result["findings"] == 38
    assert result["flagged_events"] == 35
    assert result["chains"] == 267
    assert result["chain_types"] == {"activity": 54, "download_exec": 4, "session": 209}
    assert result["cross_host_chains"] == 0
    assert result["scranton_nashua_chains"] == 0
    assert result["scenarios"] == 1
    assert result["cross_host_scenarios"] == 0
    assert result["scranton_nashua_scenarios"] == 0
    assert result["scenario_rows"] == [
        {
            "scenario_id": "scope_5ec221164a339830_scenario_chain_download_0",
            "name": "웹 다운로드 및 실행",
            "attack_stage": "execution",
            "confidence": 0.6,
            "mitre_techniques": [
                "T1003.001",
                "T1059.001",
                "T1087.002",
                "T1127.001",
                "T1140",
                "T1569.002",
            ],
            "chain_count": 4,
            "hosts": ["SCRANTON"],
        }
    ]
    assert result["largest_chains"][0]["event_count"] == 96348
    assert result["claim_boundary"]["chain_recall"] == "NOT_CLAIMED"
