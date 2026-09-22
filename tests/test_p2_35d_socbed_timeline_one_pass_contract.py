from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest
import yaml

from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35d_socbed_timeline_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35d_socbed_timeline_one_pass.py"
P2_35C_FAILURE = ROOT / "external_baseline" / "p2_35c_socbed_timeline_one_pass_failure.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35d_runner", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _timeline_lines(attacks: list[str], quoted: bool) -> str:
    lines = []
    for index, attack in enumerate(attacks):
        minute = 15 + index * 3
        if quoted:
            fields = f'event="run_attack" attack="{attack}"'
        else:
            fields = f"event=run_attack attack={attack}"
        lines.append(
            f"2021-01-01T00:{minute:02d}:00Z tbfconsole INFO "
            f"[{fields}] Run attack"
        )
    return "\n".join(lines)


def test_p2_35d_explicitly_records_post_failure_observation_boundary() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-35d-socbed-acsac2021-timeline-one-pass-v1"
    assert row["status"] == (
        "PREREGISTERED_AFTER_P2_35C_TIMING_FORMAT_FAILURE_BEFORE_JSONL_DECODING"
    )

    predecessor = row["predecessor"]
    assert predecessor["p2_35c_failure_seal_main_commit"] == (
        "c109b429ef476189bf7689682f2be75464ed9363"
    )
    assert predecessor["p2_35c_failure_stage"] == "TIMING_ANCHOR_PARSE"
    assert predecessor["selected_member_bytes_loaded_before_this_contract"] is True
    assert predecessor["selected_member_text_decoded_before_this_contract"] is False
    assert predecessor["selected_member_json_rows_parsed_before_this_contract"] is False
    assert predecessor["timing_log_decoded_before_this_contract"] is True
    assert predecessor["timing_log_quoted_structured_values_observed_before_this_contract"] is True
    assert predecessor["breachscope_detection_executed_before_this_contract"] is False
    assert predecessor["breachscope_correlation_executed_before_this_contract"] is False
    assert predecessor["breachscope_scenario_inference_executed_before_this_contract"] is False


def test_p2_35d_preserves_frozen_product_and_exact_source_bytes() -> None:
    row = _load()
    frozen = row["frozen_product"]
    assert frozen["repo_commit"] == "3ca80865477cccfa5e967f549acf32d92182eccd"
    assert frozen["rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert frozen["rule_file_count"] == 5
    assert frozen["rule_count"] == 68

    source = row["source"]
    assert source["dataset_archive"]["size_bytes"] == 77_984_817
    assert source["dataset_archive"]["sha256"] == (
        "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    )
    assert source["selected_windows_member"]["size_bytes"] == 21_081_975
    assert source["selected_windows_member"]["sha256"] == (
        "d648be6ac0acd18a354e0e1b497800d9d41d2a511afe21308ca3c2a0b679064d"
    )
    assert source["timing_anchor_member"]["content_sha256"] == (
        "e843ab909b729709b893fedc4a81c00d8d0336ff745fe05febc52ba00e9668b7"
    )


def test_p2_35d_runner_is_byte_frozen_under_new_analysis_id() -> None:
    row = _load()
    assert row["runner"]["path"] == "scripts/p2_35d_socbed_timeline_one_pass.py"
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "892babc03a073a151bdede33561740595dd1cf0821c2e838eb762b4ea6979a72"
    )
    assert row["runner"]["lock_file"] == "P2_35D_ONE_PASS.lock"

    module = _module()
    assert module.ANALYSIS_ID == "p2-35d-socbed-acsac2021-timeline-one-pass-v1"


def test_p2_35d_parser_accepts_observed_quoted_and_legacy_unquoted_syntax() -> None:
    module = _module()
    attacks = list(_load()["timeline"]["expected_attack_order"])

    quoted = module.parse_attackconsole_timeline(_timeline_lines(attacks, True), attacks)
    unquoted = module.parse_attackconsole_timeline(_timeline_lines(attacks, False), attacks)

    assert [row["attack"] for row in quoted] == attacks
    assert [row["attack"] for row in unquoted] == attacks
    assert len(quoted) == 8

    windows = module.build_step_windows(quoted, 180)
    assert len(windows) == 8
    assert all(row["window_seconds"] == 180.0 for row in windows)


def test_p2_35d_parser_still_fails_closed_on_wrong_attack_order() -> None:
    module = _module()
    attacks = list(_load()["timeline"]["expected_attack_order"])
    wrong = list(attacks)
    wrong[0], wrong[1] = wrong[1], wrong[0]

    with pytest.raises(RuntimeError, match="attackconsole run_attack order mismatch"):
        module.parse_attackconsole_timeline(_timeline_lines(wrong, True), attacks)


def test_p2_35d_parser_correction_scope_is_evaluator_only() -> None:
    row = _load()
    correction = row["parser_correction"]
    assert correction["scope"] == "EVALUATOR_TIMING_PARSER_ONLY"
    assert correction["previous_runner_sha256"] == (
        "98a4980e269e42ba99d2178a9a4849474a6620c522a052f5552ec87394962aaa"
    )
    assert correction["new_event_field_acceptance"] == [
        "event=run_attack",
        'event="run_attack"',
    ]
    assert correction["new_attack_field_acceptance_examples"] == [
        "attack=misc_sqlmap",
        'attack="misc_sqlmap"',
    ]
    assert correction["adapter_mapping_unchanged"] is True
    assert correction["temporal_window_definition_unchanged"] is True
    assert correction["measurement_outputs_unchanged"] is True
    assert correction["claim_boundaries_unchanged"] is True


def test_p2_35d_adapter_mapping_remains_unchanged_on_synthetic_row() -> None:
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
                "User": r"LAB\alice",
            },
        },
    }
    event = module.adapt_winlogbeat_row(row)
    assert isinstance(event, Event)
    assert event.timestamp == "2021-01-01T00:15:00Z"
    assert event.host == "CLIENT10"
    assert event.source == "Microsoft-Windows-Sysmon"
    assert event.event_id == "1"
    assert event.command_line == "powershell.exe -enc AAAA"
    assert event.raw["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event.raw["event_record_id"] == "42"


def test_p2_35d_protocol_is_new_one_pass_and_p2_35c_stays_immutable() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_selected_jsonl_text_decoding_or_breachscope_execution"] is True
    assert protocol["timing_log_format_was_observed_only_via_failed_p2_35c_canonical"] is True
    assert protocol["permanent_lock_required"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["p2_35c_artifacts_must_remain_immutable"] is True

    p2_35c = yaml.safe_load(P2_35C_FAILURE.read_text(encoding="utf-8"))
    assert p2_35c["status"] == "FAILED_CANONICAL"
    assert p2_35c["protocol"]["same_analysis_id_retry_allowed"] is False
    assert p2_35c["next_step"]["id"] == "P2-35D"
    assert p2_35c["next_step"]["p2_35c_must_remain_immutable"] is True


def test_p2_35d_claim_boundary_does_not_turn_temporal_coincidence_into_recall() -> None:
    claim = _load()["claim_boundary"]
    assert claim["source_attack_invocation_order"] == "NOT_YET_MEASURED"
    assert claim["temporal_window_occupancy"] == "NOT_YET_MEASURED"
    assert claim["attack_step_semantic_attribution"] == "NOT_EVALUATED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["chain_precision"] == "NOT_EVALUATED"
    assert claim["chain_recall"] == "NOT_EVALUATED"
    assert claim["scenario_precision"] == "NOT_EVALUATED"
    assert claim["scenario_recall"] == "NOT_EVALUATED"
    assert claim["production_reconstruction_quality"] == "NOT_CLAIMED"
