from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "p2_35e_socbed_timeline_one_pass_result.yaml"
RAW = ROOT / "external_baseline" / "results" / "p2_35e_e4561e3" / "result.json"
LOCK = ROOT / "external_baseline" / "locks" / "P2_35E_ONE_PASS.lock"
CONTRACT = ROOT / "external_baseline" / "p2_35e_socbed_timeline_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35e_socbed_timeline_one_pass.py"
P2_35D = ROOT / "external_baseline" / "p2_35d_socbed_timeline_one_pass_failure.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_35e_canonical_artifacts_are_byte_exact() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == (
        "e4561e34b5d80a3539c671ebfd3cfeae487b2caf"
    )
    assert row["canonical_repo_commit"] == (
        "e4561e34b5d80a3539c671ebfd3cfeae487b2caf"
    )

    assert RAW.stat().st_size == 11_288
    assert LOCK.stat().st_size == 115
    assert _sha256(RAW) == (
        "2ddefd866f335a7f6c5aca4951344373a95bacabab92f9de32e58263d0b26b17"
    )
    assert _sha256(LOCK) == (
        "a0dd97a531ee41f86b3b4c32fefe3baf6b70b721379533c12f26b0bb9342e5b7"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert (
        row["canonical_artifacts"]["permanent_global_lock"]["sha256"]
        == _sha256(LOCK)
    )


def test_p2_35e_raw_result_completed_with_frozen_inputs() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["analysis_id"] == "p2-35e-socbed-acsac2021-timeline-one-pass-v1"
    assert raw["contract_sha256"] == _sha256(CONTRACT)
    assert raw["runner_sha256"] == _sha256(RUNNER)
    assert raw["contract_sha256"] == (
        "f57eb39dc14aef054db4fc4d87a5e096e5bbf408793dc294a14622f6c815a8c9"
    )
    assert raw["runner_sha256"] == (
        "bffd71419b11ad6e2ac1032ccfe904d7844e3a3a9f6159d6d9e7adeeeb83fca3"
    )
    assert raw["product"]["baseline_repo_commit"] == (
        "3ca80865477cccfa5e967f549acf32d92182eccd"
    )
    assert raw["product"]["breachscope_and_rules_match_frozen_commit"] is True
    assert raw["source"]["archive_sha256"] == (
        "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    )
    assert raw["source"]["selected_windows_member"]["sha256"] == (
        "d648be6ac0acd18a354e0e1b497800d9d41d2a511afe21308ca3c2a0b679064d"
    )
    assert raw["source"]["timing_anchor_member"]["sha256"] == (
        "e843ab909b729709b893fedc4a81c00d8d0336ff745fe05febc52ba00e9668b7"
    )


def test_p2_35e_timeline_and_measurement_counts_are_sealed() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    measurement = raw["measurement"]
    alignment = measurement["timeline_alignment"]

    assert len(raw["timeline"]["attacks"]) == 8
    assert [row["attack"] for row in raw["timeline"]["attacks"]] == [
        "misc_sqlmap",
        "infect_email_exe",
        "c2_take_screenshot",
        "c2_exfiltration",
        "c2_mimikatz",
        "misc_download_malware",
        "misc_set_autostart",
        "misc_execute_malware",
    ]

    assert measurement["raw_jsonl_rows"] == 9_370
    assert measurement["events"] == 9_369
    assert measurement["unknown_host_events"] == 0
    assert measurement["unknown_source_events"] == 0
    assert measurement["missing_event_id_events"] == 0
    assert measurement["findings"] == 29
    assert measurement["chains"] == 42
    assert measurement["scenarios"] == 1

    assert alignment["step_count"] == 8
    assert alignment["steps_with_events"] == 8
    assert alignment["steps_with_findings"] == 2
    assert alignment["steps_with_chain_starts"] == 4
    assert alignment["steps_with_scenario_starts"] == 1
    assert alignment["finding_window_occupancy_fraction"] == 0.25
    assert alignment["chain_start_window_occupancy_fraction"] == 0.5
    assert alignment["scenario_start_window_occupancy_fraction"] == 0.125


def test_p2_35e_per_step_temporal_observations_are_exact() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    steps = raw["measurement"]["timeline_alignment"]["steps"]

    projection = [
        (
            row["attack"],
            row["event_count"],
            row["finding_count"],
            row["chain_start_count"],
            row["scenario_start_count"],
        )
        for row in steps
    ]
    assert projection == [
        ("misc_sqlmap", 199, 0, 0, 0),
        ("infect_email_exe", 340, 0, 0, 0),
        ("c2_take_screenshot", 168, 0, 0, 0),
        ("c2_exfiltration", 182, 0, 2, 0),
        ("c2_mimikatz", 167, 4, 6, 1),
        ("misc_download_malware", 141, 5, 8, 0),
        ("misc_set_autostart", 205, 0, 3, 0),
        ("misc_execute_malware", 119, 0, 0, 0),
    ]


def test_p2_35e_temporal_occupancy_is_not_semantic_attribution_or_recall() -> None:
    row = _load()
    decision = row["decision"]
    assert decision["canonical_execution"] == "COMPLETED"
    assert decision["source_attack_order"] == "MEASURED"
    assert decision["all_eight_windows_contain_events"] is True
    assert decision["temporal_finding_occupancy_observed"] == "2_OF_8_WINDOWS"
    assert decision["temporal_chain_start_occupancy_observed"] == "4_OF_8_WINDOWS"
    assert decision["temporal_scenario_start_occupancy_observed"] == "1_OF_8_WINDOWS"
    assert decision["semantic_attack_attribution_authorized"] is False
    assert decision["precision_or_recall_claim_authorized"] is False

    claim = row["claim_boundary"]
    assert claim["source_attack_invocation_order"] == "MEASURED_FROM_SOURCE_TIMING_LOG"
    assert claim["temporal_window_occupancy"] == "MEASURED"
    assert claim["attack_step_semantic_attribution"] == "NOT_EVALUATED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["chain_precision"] == "NOT_EVALUATED"
    assert claim["chain_recall"] == "NOT_EVALUATED"
    assert claim["scenario_precision"] == "NOT_EVALUATED"
    assert claim["scenario_recall"] == "NOT_EVALUATED"
    assert claim["production_reconstruction_quality"] == "NOT_CLAIMED"


def test_p2_35e_protocol_records_one_global_lock_and_no_duplicate() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["permanent_analysis_id_global_lock_used"] is True
    assert protocol["first_lock_acquired_execution_retained_as_canonical"] is True
    assert protocol["duplicate_p2_35e_canonical_execution_performed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert protocol["product_or_rules_modified_after_canonical"] is False
    assert protocol["p2_35d_artifacts_modified"] is False

    lock_payload = json.loads(LOCK.read_text(encoding="utf-8"))
    assert lock_payload["analysis_id"] == (
        "p2-35e-socbed-acsac2021-timeline-one-pass-v1"
    )

    predecessor = yaml.safe_load(P2_35D.read_text(encoding="utf-8"))
    assert predecessor["status"] == "FAILED_CANONICAL"
    assert predecessor["protocol"]["same_analysis_id_retry_allowed"] is False
    assert predecessor["next_step"]["id"] == "P2-35E"
    assert predecessor["next_step"]["p2_35d_must_remain_immutable"] is True


def test_p2_35e_global_lock_is_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "external_baseline/locks/P2_35E_ONE_PASS.lock -text -whitespace"
        in attrs
    )
