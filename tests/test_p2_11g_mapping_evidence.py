from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "results" / "p2_11g_e876ce32"
MEASUREMENT = EVIDENCE / "measurement.yaml"
AGGREGATE = EVIDENCE / "aggregate-result.json"
FREEZE = EVIDENCE / "rules-freeze.json"
RULE_HASH = "1626aca8b7b9a8e2a7e1f42360c65b504827ff43e52159eb3716613ebb540a50"
AGGREGATE_SHA256 = "5be90a775a2b6f5216a61ab0b061a095797bd302f4480caa6916fef79f83431b"
FREEZE_SHA256 = "73535d68e868b1918a30fddb8ac7678b42908ef96f21d9f6629080eef81a983f"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_11g_measurement_records_mapping_only_transition() -> None:
    data = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.p2_11g_mapping_calibration_measurement.v1"
    assert data["calibration_id"] == "p2-11g-t1027-encoded-powershell-mapping"
    assert data["measurement_class"] == "external_calibration"
    assert data["change_class"] == "technique_mapping_and_evaluator_semantics_only"
    assert data["measurement_repo_commit"] == "e876ce32c6b5c9846ca553b03a291548a7a7aa93"
    assert data["from_rules_tree_sha256"] == RULE_HASH
    assert data["to_rules_tree_sha256"] == RULE_HASH
    assert data["predicate_change"] is False

    mapping = data["mapping_change"]
    assert mapping["rule_id"] == "R-ENC"
    assert mapping["primary_technique"] == "T1059.001"
    assert mapping["additional_techniques"] == ["T1027.010"]
    assert mapping["expected_parent_technique"] == "T1027"
    assert mapping["evaluator_relation"] == "parent_requirement_may_be_satisfied_by_child"
    assert mapping["duplicate_findings_introduced"] is False


def test_p2_11g_external_calibration_is_exactly_5_to_6_of_12() -> None:
    data = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    calibration = data["external_calibration"]

    assert calibration["previous_measurement_record"] == (
        "external_baseline/results/p2_11f_e2f78b3a/measurement.yaml"
    )
    assert calibration["source_repository"] == "arniki/atomic-evtx"
    assert calibration["source_commit"] == "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
    assert calibration["selection_frozen_commit"] == "7541214400507afddca40a22f2adb22504fc3946"
    assert calibration["before_scenario_hits"] == 5
    assert calibration["after_scenario_hits"] == 6
    assert calibration["scenario_misses"] == 6
    assert calibration["scenario_total"] == 12
    assert calibration["events"] == 902
    assert calibration["rules"] == 64
    assert calibration["findings"] == 89
    assert calibration["flagged_events"] == 85
    assert calibration["changed_scenarios"] == ["T1027-2"]
    assert calibration["remaining_miss_scenarios"] == [
        "T1003-1",
        "T1003-2",
        "T1021.001-1",
        "T1021.001-2",
        "T1047-1",
        "T1047-2",
    ]


def test_p2_11g_artifact_bytes_and_execution_metadata_are_locked() -> None:
    data = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    execution = data["measurement_execution"]

    assert execution["github_actions_run_id"] == 34499756767
    assert execution["workflow_control_head_commit"] == "913e7c6d58992e382ab06c419c308fcb52ccba09"
    assert execution["detector_repo_commit"] == "e876ce32c6b5c9846ca553b03a291548a7a7aa93"
    assert execution["artifact_id"] == 10161361100
    assert execution["artifact_digest_sha256"] == "2b0f3e8debc4bd72ee8e7d9ed33dcdb487a5111916e7bacdd886e3bc173aefa0"
    assert execution["aggregate_result_sha256"] == AGGREGATE_SHA256
    assert execution["artifact_inner_aggregate_result_sha256"] == AGGREGATE_SHA256
    assert execution["rules_freeze_sha256"] == FREEZE_SHA256
    assert execution["freeze_probe_run_id"] == 34499756832
    assert execution["freeze_probe_artifact_id"] == 10161345939
    assert execution["freeze_probe_artifact_digest_sha256"] == (
        "ad9a87db7b71383706eea1fa5b00312067e401f10c4799fa0476adbd697cc877"
    )
    assert _sha256(AGGREGATE) == AGGREGATE_SHA256
    assert _sha256(FREEZE) == FREEZE_SHA256


def test_p2_11g_aggregate_confirms_t1027_parent_hit_without_predicate_change() -> None:
    aggregate = json.loads(AGGREGATE.read_text(encoding="utf-8"))

    assert aggregate["schema"] == "breachscope.p2_11g_external_calibration_result.v1"
    assert aggregate["evaluation_class"] == "external_calibration"
    assert aggregate["change_class"] == "technique_mapping_and_evaluator_semantics_only"
    assert aggregate["detector_repo_commit"] == "e876ce32c6b5c9846ca553b03a291548a7a7aa93"
    assert aggregate["rules_tree_sha256"] == RULE_HASH
    assert aggregate["rules_tree_changed_from_p2_11f"] is False
    assert aggregate["predicate_change"] is False
    assert aggregate["rules"] == 64
    assert aggregate["events"] == 902
    assert aggregate["findings"] == 89
    assert aggregate["flagged_events"] == 85
    assert aggregate["previous_p2_11f_findings"] == 89
    assert aggregate["previous_p2_11f_flagged_events"] == 85
    assert aggregate["scenario_hits"] == 6
    assert aggregate["scenario_misses"] == 6
    assert aggregate["scenario_total"] == 12

    outcomes = {row["scenario_id"]: row for row in aggregate["outcomes"]}
    t1027 = outcomes["T1027-2"]
    assert t1027["expected_techniques"] == ["T1027"]
    assert t1027["matched_techniques"] == ["T1027"]
    assert t1027["missing_techniques"] == []
    assert "T1027.010" in t1027["observed_techniques"]
    assert "T1059.001" in t1027["observed_techniques"]
    assert t1027["status"] == "hit"


def test_p2_11g_claim_boundaries_remain_nonblind_and_nonproduction() -> None:
    measurement = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    aggregate = json.loads(AGGREGATE.read_text(encoding="utf-8"))

    for claims in (measurement["claim_boundary"], aggregate["claim_boundary"]):
        assert claims["final_blind_holdout"] is False
        assert claims["fresh_external_baseline"] is False
        for key in (
            "production_detection_rate",
            "production_precision",
            "production_recall",
            "production_false_positive_rate",
        ):
            assert claims[key] == "NOT_CLAIMED"

    event_level = aggregate["event_level"]
    assert event_level["labels"] == "all_ignore"
    assert event_level["scored_events"] == 0
    assert event_level["precision"] == "NOT_CLAIMED"
    assert event_level["recall"] == "NOT_CLAIMED"
    assert event_level["false_positive_rate"] == "NOT_CLAIMED"


def test_p2_11g_runtime_freeze_is_exact_core_commit_and_same_rule_tree() -> None:
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))

    assert freeze["schema"] == "breachscope.external_holdout.rules_freeze.v1"
    assert freeze["repo_commit"] == "e876ce32c6b5c9846ca553b03a291548a7a7aa93"
    assert freeze["rules_tree_sha256"] == RULE_HASH
    assert freeze["rule_file_count"] == 4
