from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "results" / "p2_11h_7f46b3a2"
MEASUREMENT = EVIDENCE / "measurement.yaml"
AGGREGATE = EVIDENCE / "aggregate-result.json"
FREEZE = EVIDENCE / "rules-freeze.json"
BENIGN = EVIDENCE / "benign-probe.json"

FROM_RULE_HASH = "1626aca8b7b9a8e2a7e1f42360c65b504827ff43e52159eb3716613ebb540a50"
TO_RULE_HASH = "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
AGGREGATE_SHA256 = "137a445d293f1659a965cd62f2f15a0966b9a1ce375d4a0714ad2f442c11dc1e"
FREEZE_SHA256 = "7ae70b315c92a3a1c2030fb5b787059218216759d7e15350e563eda8dc5961d6"
BENIGN_SHA256 = "33bd265a51625bf104078b7a91ff63a0a83e32606c17af825224d56d2bff2789"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_11h_measurement_records_exact_wmic_rule_transition() -> None:
    data = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.p2_11h_external_calibration_measurement.v1"
    assert data["calibration_id"] == "p2-11h-t1047-wmic-query"
    assert data["measurement_class"] == "external_calibration"
    assert data["change_class"] == "wmic_query_telemetry_rule_addition"
    assert data["measurement_repo_commit"] == "7f46b3a29306328716dc02c176b4501eb2ef261b"
    assert data["from_rules_tree_sha256"] == FROM_RULE_HASH
    assert data["to_rules_tree_sha256"] == TO_RULE_HASH

    change = data["rule_change"]
    assert change["rule_file"] == "rules/p2_11_calibration_rules.yml"
    assert change["rule_file_git_blob_sha1"] == "0571c33e8d3ab0a7c25ab91a4fb9594a8c2b9c75"
    assert len(change["rules"]) == 1
    rule = change["rules"][0]
    assert rule["rule_id"] == "R-WMI-QUERY-GET"
    assert rule["mitre_technique"] == "T1047"
    assert rule["predicate"] == {
        "source_equals": "Microsoft-Windows-Sysmon",
        "event_id_equals": "1",
        "image_endswith": r"\wmic.exe",
        "command_line_regex": r"^(?!.*\/format\s*:\s*.*https?:\/\/).*\bget\b",
    }


def test_p2_11h_benign_probe_is_locked_and_zero_for_candidate_predicates() -> None:
    data = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    benign_meta = data["benign_incremental_match_proof"]
    benign = json.loads(BENIGN.read_text(encoding="utf-8"))

    assert _sha256(BENIGN) == BENIGN_SHA256
    assert benign_meta["probe_run_id"] == 34554436633
    assert benign_meta["probe_commit"] == "7607c9abdd8015d360ca624758805f6efe41ff6f"
    assert benign_meta["artifact_id"] == 10182076804
    assert benign_meta["artifact_digest_sha256"] == "ef512726590305b95802e74ccc222d6c89e06102c6bf91f3667eaaec8c920704"
    assert benign_meta["artifact_inner_result_sha256"] == BENIGN_SHA256
    assert benign_meta["stored_result_sha256"] == BENIGN_SHA256
    assert benign_meta["fresh_full_fp_tn_rerun"] is False

    assert benign["schema"] == "breachscope.p2_11h_t1047_benign_probe.v1"
    assert benign["corpus_sha256"] == "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    assert benign["scope"] == {
        "sysmon_records": 732200,
        "sysmon_chunks": 11894,
        "sysmon_event1": 2149,
        "parse_errors": 0,
    }
    assert benign["candidate_counts"] == {
        "wmic_event1": 0,
        "wmic_get_any": 0,
        "wmic_get_non_remote_xsl": 0,
        "wmic_useraccount_get": 0,
        "wmic_process_get": 0,
        "wmic_user_or_process_get": 0,
        "wmic_get_format_csv": 0,
        "wmic_get_remote_format_http": 0,
    }
    assert benign["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert benign["claim_boundary"]["fresh_full_rulepack_fpr"] == "NOT_CLAIMED"


def test_p2_11h_external_calibration_is_exactly_6_to_8_of_12() -> None:
    data = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    calibration = data["external_calibration"]

    assert calibration["previous_measurement_record"] == (
        "external_baseline/results/p2_11g_e876ce32/measurement.yaml"
    )
    assert calibration["source_repository"] == "arniki/atomic-evtx"
    assert calibration["source_commit"] == "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
    assert calibration["selection_frozen_commit"] == "7541214400507afddca40a22f2adb22504fc3946"
    assert calibration["before_scenario_hits"] == 6
    assert calibration["after_scenario_hits"] == 8
    assert calibration["scenario_misses"] == 4
    assert calibration["scenario_total"] == 12
    assert calibration["events"] == 902
    assert calibration["rules"] == 65
    assert calibration["findings"] == 91
    assert calibration["flagged_events"] == 87
    assert calibration["changed_scenarios"] == ["T1047-1", "T1047-2"]
    assert calibration["remaining_miss_scenarios"] == [
        "T1003-1",
        "T1003-2",
        "T1021.001-1",
        "T1021.001-2",
    ]


def test_p2_11h_artifact_bytes_and_execution_metadata_are_locked() -> None:
    data = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    execution = data["measurement_execution"]

    assert execution["github_actions_run_id"] == 34555286447
    assert execution["workflow_control_head_commit"] == "722b1a9e23a91b1836ae06a119687d4a284554c2"
    assert execution["detector_repo_commit"] == "7f46b3a29306328716dc02c176b4501eb2ef261b"
    assert execution["artifact_id"] == 10182325376
    assert execution["artifact_digest_sha256"] == "420df5a561b6d50489119bffa794d07ddbb94551cda77e8dc9d3b91fbdfcf0fd"
    assert execution["aggregate_result_sha256"] == AGGREGATE_SHA256
    assert execution["artifact_inner_aggregate_result_sha256"] == AGGREGATE_SHA256
    assert execution["rules_freeze_sha256"] == FREEZE_SHA256
    assert execution["freeze_probe_run_id"] == 34555286457
    assert execution["freeze_probe_artifact_id"] == 10182311143
    assert execution["freeze_probe_artifact_digest_sha256"] == (
        "edd77d62ab36e25b13e1dc2611fd797c9cd828e82bbf1b55acd142092a149c55"
    )
    assert _sha256(AGGREGATE) == AGGREGATE_SHA256
    assert _sha256(FREEZE) == FREEZE_SHA256


def test_p2_11h_aggregate_confirms_only_t1047_scenarios_newly_hit() -> None:
    aggregate = json.loads(AGGREGATE.read_text(encoding="utf-8"))

    assert aggregate["schema"] == "breachscope.p2_11h_external_calibration_result.v1"
    assert aggregate["evaluation_class"] == "external_calibration"
    assert aggregate["change_class"] == "wmic_query_telemetry_rule_addition"
    assert aggregate["detector_repo_commit"] == "7f46b3a29306328716dc02c176b4501eb2ef261b"
    assert aggregate["rules_tree_sha256"] == TO_RULE_HASH
    assert aggregate["rules"] == 65
    assert aggregate["events"] == 902
    assert aggregate["findings"] == 91
    assert aggregate["flagged_events"] == 87
    assert aggregate["scenario_hits"] == 8
    assert aggregate["scenario_misses"] == 4
    assert aggregate["scenario_total"] == 12

    outcomes = {row["scenario_id"]: row for row in aggregate["outcomes"]}
    assert [sid for sid, row in outcomes.items() if row["status"] == "hit"] == [
        "T1006-1",
        "T1027-2",
        "T1007-1",
        "T1007-2",
        "T1047-1",
        "T1047-2",
        "T1136.001-4",
        "T1136.001-5",
    ]
    for sid in ("T1047-1", "T1047-2"):
        assert outcomes[sid]["expected_techniques"] == ["T1047"]
        assert outcomes[sid]["matched_techniques"] == ["T1047"]
        assert outcomes[sid]["missing_techniques"] == []
        assert outcomes[sid]["status"] == "hit"


def test_p2_11h_claim_boundaries_remain_nonblind_and_nonproduction() -> None:
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


def test_p2_11h_runtime_freeze_is_exact_core_commit_and_new_rule_tree() -> None:
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))

    assert freeze["schema"] == "breachscope.external_holdout.rules_freeze.v1"
    assert freeze["repo_commit"] == "7f46b3a29306328716dc02c176b4501eb2ef261b"
    assert freeze["rules_tree_sha256"] == TO_RULE_HASH
    assert freeze["rule_file_count"] == 4
