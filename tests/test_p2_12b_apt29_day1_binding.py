from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_12b_apt29_day1_binding.yaml"


def test_p2_12b_byte_binding_is_exact() -> None:
    data = yaml.safe_load(BINDING.read_text(encoding="utf-8"))
    archive = data["archive_binding"]
    plan = data["emulation_plan_binding"]

    assert data["schema"] == "breachscope.p2_12b_fresh_external_binding.v1"
    assert archive["git_blob_sha1"] == "7352679a173ec0310f9d0ed587782545182dd394"
    assert archive["sha256"] == "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5"
    assert archive["compressed_bytes"] == 13944973
    assert archive["member_count"] == 1
    assert archive["member_name"] == "apt29_evals_day1_manual_2020-05-01225525.json"
    assert archive["member_uncompressed_bytes"] == 385334029
    assert plan["git_blob_sha1"] == "e2b95dc306967a6a2d9af033cf1fe7c3ad155c13"
    assert plan["sha256"] == "053e70c6ba95eac481b370f8b1545ec3f1f00306c828634741a8c7399719c228"
    assert plan["bytes"] == 25051


def test_p2_12b_actual_archive_counts_are_locked() -> None:
    data = yaml.safe_load(BINDING.read_text(encoding="utf-8"))
    counts = data["actual_archive_counts"]

    assert counts["total_events"] == 196081
    assert counts["parse_errors"] == 0
    assert counts["channels"]["Microsoft-Windows-Sysmon/Operational"] == 143884
    assert counts["channels"]["Security"] == 28627
    assert counts["channels"]["security"] == 12375
    assert counts["sysmon_event_ids"]["1"] == 447
    assert counts["sysmon_event_ids"]["10"] == 39283
    conflict = data["metadata_conflict_resolution"]
    assert conflict["parent_readme_sysmon_records"] == 143884
    assert conflict["day1_readme_sysmon_records"] == 164435
    assert conflict["authoritative_for_p2_12"] == "actual_archive_parse"
    assert conflict["resolved_sysmon_records"] == 143884


def test_p2_12b_labels_are_bound_before_detection() -> None:
    data = yaml.safe_load(BINDING.read_text(encoding="utf-8"))
    labels = data["label_binding"]
    state = data["protocol_state"]

    assert data["emulation_plan_binding"]["worksheet"] == "day1"
    assert labels["labeled_rows"] == 25
    assert labels["unique_technique_count"] == 45
    assert len(labels["technique_ids"]) == 45
    assert len(set(labels["technique_ids"])) == 45
    assert labels["semantics"] == "exact_upstream_legacy_attack_ids_no_post_result_remapping"
    assert labels["event_level_labels"] == "NOT_AVAILABLE"
    assert state["selection_frozen_before_byte_download"] is True
    assert state["archive_bytes_bound"] is True
    assert state["emulation_plan_bytes_bound"] is True
    assert state["labels_bound_before_detection"] is True
    assert state["detector_executed_on_selected_archive"] is False
    assert state["detector_results_consulted"] is False
    assert state["day2_reserved_unscored"] is True
    assert state["next_allowed_phase"] == "P2-12C_FRESH_SCORING"


def test_p2_12b_claim_boundaries_are_explicit() -> None:
    claims = yaml.safe_load(BINDING.read_text(encoding="utf-8"))["claim_boundary"]
    assert claims["fresh_external_holdout_result"] == "NOT_YET_MEASURED"
    assert claims["production_detection_rate"] == "NOT_CLAIMED"
    assert claims["production_precision"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
