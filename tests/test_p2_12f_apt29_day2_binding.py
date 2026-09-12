from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_12f_apt29_day2_binding.yaml"


def _load():
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_12f_binds_exact_day2_bytes_and_actual_parse() -> None:
    d = _load()
    assert d["schema"] == "breachscope.p2_12f_confirmatory_binding.v1"
    assert d["evaluation_class"] == "confirmatory_same_campaign_holdout_pre_scoring"
    assert d["frozen_detector"] == {
        "repo_commit": "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb",
        "rules_tree_sha256": "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92",
        "rule_count": 66,
    }
    src = d["source_binding"]
    assert src["archive_git_blob_sha1"] == "15e1e9d2d88a729b832c6430fa285c3e87bb70e4"
    assert src["archive_size_bytes"] == 43033041
    assert src["archive_sha256"] == "377f8cba5db95a453a3ee8bd19f493efafc23724541482a4da99da28ee4665f9"
    assert src["member_count"] == 1
    assert src["member_name"] == "apt29_evals_day2_manual_2020-05-02035409.json"
    assert src["member_uncompressed_bytes"] == 1714987031
    actual = d["actual_archive_parse"]
    assert actual["total_events"] == 587286
    assert actual["parse_errors"] == 0
    assert actual["channels"]["Microsoft-Windows-Sysmon/Operational"] == 407265
    assert actual["sysmon_event_ids"]["1"] == 581


def test_p2_12f_freezes_day2_labels_before_scoring() -> None:
    d = _load()
    plan = d["emulation_plan_binding"]
    assert plan["sha256"] == "053e70c6ba95eac481b370f8b1545ec3f1f00306c828634741a8c7399719c228"
    assert plan["worksheet"] == "day2"
    assert plan["labeled_rows"] == 24
    assert plan["unique_technique_count"] == 41
    assert plan["technique_ids"] == [
        "T1002", "T1003", "T1005", "T1012", "T1016", "T1018", "T1027", "T1028",
        "T1032", "T1033", "T1043", "T1047", "T1048", "T1055", "T1057", "T1060",
        "T1063", "T1071", "T1074", "T1078", "T1082", "T1083", "T1084", "T1085",
        "T1086", "T1088", "T1096", "T1097", "T1099", "T1102", "T1103", "T1105",
        "T1106", "T1107", "T1114", "T1120", "T1122", "T1136", "T1140", "T1204",
        "T1497",
    ]


def test_p2_12f_execution_and_claim_boundaries_remain_fail_closed() -> None:
    d = _load()
    execution = d["execution_binding"]
    assert execution["github_actions_run_id"] == 34664936441
    assert execution["control_head_commit"] == "5067f8111863686f658315bdc7333d603aea6f3a"
    assert execution["artifact_id"] == 10288149802
    assert execution["artifact_digest_sha256"] == "a4aad753dd0fc9dd438e47f2f677f39881cba606f0270116fca6498f3e73a2eb"
    assert execution["artifact_inner_result_sha256"] == "ea13cc6b89fa4c424d81ebca1b14b4385420f1f3a75e92a618f8979acf2c410f"
    assert d["independence_boundary"] == {
        "classification": "confirmatory_same_campaign_holdout",
        "independent_fresh_external_holdout": False,
        "same_repository_as_day1": True,
        "same_campaign_as_day1": True,
    }
    state = d["protocol_state"]
    assert state["selection_committed_before_archive_download"] is True
    assert state["archive_bytes_bound_before_detection"] is True
    assert state["day2_labels_bound_before_detection"] is True
    assert state["detector_imported"] is False
    assert state["detector_executed_on_day2"] is False
    assert state["detector_results_viewed"] is False
    assert state["tuning_after_day1_before_day2_forbidden"] is True
    assert state["next_allowed_phase"] == "P2-12G_DAY2_CONFIRMATORY_SCORING"
    claims = d["claim_boundary"]
    assert claims["confirmatory_holdout_result"] == "NOT_YET_MEASURED"
    assert claims["independent_fresh_external_holdout"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
