from __future__ import annotations

import hashlib
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import yaml

from breachscope.schemas import Event, Finding


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35c_socbed_timeline_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35c_socbed_timeline_one_pass.py"
P2_35B = ROOT / "external_baseline" / "p2_35b_socbed_phase_b_assessment.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35c_runner", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p2_35c_is_preobservation_and_preserves_frozen_product() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_BEFORE_EVENT_CONTENT_OBSERVATION"
    assert row["predecessor"]["phase_b_main_commit"] == (
        "39ccfd3bc86b552a35b35dc9705fb84f4b5e472f"
    )
    assert row["predecessor"]["selected_member_content_observed_before_this_contract"] is False
    assert row["predecessor"]["timing_log_content_observed_before_this_contract"] is False

    frozen = row["frozen_product"]
    assert frozen["repo_commit"] == "3ca80865477cccfa5e967f549acf32d92182eccd"
    assert frozen["rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert frozen["rule_file_count"] == 5
    assert frozen["rule_count"] == 68
    assert frozen["product_or_rules_change_before_measurement_allowed"] is False


def test_p2_35c_runner_and_exact_source_bytes_are_frozen() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "98a4980e269e42ba99d2178a9a4849474a6620c522a052f5552ec87394962aaa"
    )

    source = row["source"]
    assert source["dataset_archive"]["size_bytes"] == 77_984_817
    assert source["dataset_archive"]["sha256"] == (
        "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    )
    selected = source["selected_windows_member"]
    assert selected["path"] == "host1_bestpractice/winlogbeat_01.jsonl"
    assert selected["size_bytes"] == 21_081_975
    assert selected["sha256"] == (
        "d648be6ac0acd18a354e0e1b497800d9d41d2a511afe21308ca3c2a0b679064d"
    )
    assert source["timing_anchor_member"]["path"] == (
        "host1_bestpractice/attackconsole_01.log"
    )
    assert source["timing_anchor_member"]["size_bytes"] == 6536


def test_p2_35c_timing_format_reference_is_byte_bound() -> None:
    ref = _load()["timing_log_format_reference"]
    assert ref["repository"] == "fkie-cad/socbed"
    assert ref["commit"] == "92ca444fac425a18141d90b09e3c9f8e7976dff4"
    assert ref["git_blob_sha1"] == "4a4b3725c4cff1efd2bb7391cd9bb49a5b0c3177"
    assert ref["sha256"] == (
        "cbcef9c4407fe18752aa124acc3837caa711d9b2437159e49746cd9ffea6d148"
    )


def test_p2_35c_adapter_maps_synthetic_winlogbeat_without_source_observation() -> None:
    module = _module()
    row = {
        "@timestamp": "2021-01-01T00:15:00Z",
        "host": {"name": "collector"},
        "winlog": {
            "computer_name": "CLIENT10",
            "provider_name": "Microsoft-Windows-Sysmon",
            "event_id": 1,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 42,
            "event_data": {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentImage": r"C:\Windows\explorer.exe",
                "CommandLine": "powershell.exe -enc AAAA",
                "User": "LAB\\alice",
            },
        },
    }
    event = module.adapt_winlogbeat_row(row)
    assert event.timestamp == "2021-01-01T00:15:00Z"
    assert event.host == "CLIENT10"
    assert event.source == "Microsoft-Windows-Sysmon"
    assert event.event_id == "1"
    assert event.command_line == "powershell.exe -enc AAAA"
    assert event.raw["Image"].endswith("powershell.exe")
    assert event.raw["ParentImage"].endswith("explorer.exe")
    assert event.raw["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event.raw["event_record_id"] == "42"


def test_p2_35c_timeline_parser_requires_exact_eight_step_order() -> None:
    module = _module()
    attacks = list(_load()["timeline"]["expected_attack_order"])
    lines = []
    for index, attack in enumerate(attacks):
        minute = 15 + index * 3
        lines.append(
            f"2021-01-01T00:{minute:02d}:00Z tbfconsole INFO "
            f"[event=run_attack attack={attack}] Run attack"
        )
    timeline = module.parse_attackconsole_timeline("\n".join(lines), attacks)
    assert [row["attack"] for row in timeline] == attacks
    windows = module.build_step_windows(timeline, 180)
    assert len(windows) == 8
    assert all(row["window_seconds"] == 180.0 for row in windows)


def test_p2_35c_alignment_records_temporal_occupancy_not_semantic_recall() -> None:
    module = _module()
    attacks = list(_load()["timeline"]["expected_attack_order"])
    base = datetime(2021, 1, 1, 0, 15, tzinfo=timezone.utc)
    timeline = [
        {
            "ordinal": index + 1,
            "attack": attack,
            "_dt": base.replace(minute=15 + index * 3),
        }
        for index, attack in enumerate(attacks)
    ]
    windows = module.build_step_windows(timeline, 180)

    event1 = Event(
        timestamp="2021-01-01T00:15:10Z",
        host="CLIENT10",
        source="Microsoft-Windows-Sysmon",
        event_id="1",
        raw={},
    )
    event2 = Event(
        timestamp="2021-01-01T00:18:20Z",
        host="CLIENT10",
        source="Microsoft-Windows-Sysmon",
        event_id="1",
        raw={},
    )
    finding = Finding(
        rule_id="synthetic",
        rule_name="Synthetic",
        severity="high",
        mitre_technique="T1059.001",
        event=event1,
        matched_value="powershell",
    )
    chain = SimpleNamespace(
        start_time=datetime(2021, 1, 1, 0, 18, 30, tzinfo=timezone.utc),
        chain_type="download_exec",
    )
    scenario_chain = SimpleNamespace(start_time="2021-01-01T00:21:30+00:00")
    scenario = SimpleNamespace(
        chains=[scenario_chain],
        attack_stage="execution",
    )

    result = module.summarize_alignment(
        [event1, event2], [finding], [chain], [scenario], windows
    )
    assert result["steps_with_events"] == 2
    assert result["steps_with_findings"] == 1
    assert result["steps_with_chain_starts"] == 1
    assert result["steps_with_scenario_starts"] == 1
    assert result["steps"][0]["attack"] == "misc_sqlmap"
    assert result["steps"][0]["finding_count"] == 1
    assert result["steps"][1]["chain_start_count"] == 1
    assert result["steps"][2]["scenario_start_count"] == 1

    claim = _load()["claim_boundary"]
    assert claim["attack_step_semantic_attribution"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["chain_recall"] == "NOT_EVALUATED"
    assert claim["scenario_recall"] == "NOT_EVALUATED"


def test_p2_35c_protocol_is_one_pass_and_fail_closed() -> None:
    row = _load()
    protocol = row["protocol"]
    assert (
        protocol[
            "contract_must_merge_before_selected_jsonl_or_timing_log_content_observation"
        ]
        is True
    )
    assert protocol["permanent_lock_required"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["runner_change_requires_new_analysis_id"] is True
    assert protocol["adapter_change_requires_new_analysis_id"] is True
    assert protocol["scoring_change_requires_new_analysis_id"] is True

    phase_b = yaml.safe_load(P2_35B.read_text(encoding="utf-8"))
    assert phase_b["protocol"]["selected_member_content_observed"] is False
    assert phase_b["protocol"]["timing_log_content_observed"] is False
    assert phase_b["protocol"]["breachscope_detector_executed"] is False
