from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35e_socbed_timeline_one_pass_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35e_socbed_timeline_one_pass.py"
P2_35D_FAILURE = ROOT / "external_baseline" / "p2_35d_socbed_timeline_one_pass_failure.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35e_runner", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _timeline_lines(attacks: list[str], quoted: bool) -> str:
    rows = []
    for index, attack in enumerate(attacks):
        minute = 15 + index * 3
        if quoted:
            fields = f'event="run_attack" attack="{attack}"'
        else:
            fields = f"event=run_attack attack={attack}"
        rows.append(
            f"2021-01-01T00:{minute:02d}:00Z tbfconsole INFO [{fields}] Run attack"
        )
    return "\n".join(rows)


def test_p2_35e_records_p2_35d_failure_and_duplicate_violation() -> None:
    row = _load()
    assert row["status"] == (
        "PREREGISTERED_AFTER_P2_35D_IMPORT_FAILURE_BEFORE_SELECTED_JSONL_DECODING"
    )
    pred = row["predecessor"]
    assert pred["p2_35d_contract_main_commit"] == (
        "bea00124dc7f50ff901beda2846b3e48c0d9b6f5"
    )
    assert pred["p2_35d_failure_main_commit"] == (
        "e61e35322a7382f60efbad55c9279b007684d00d"
    )
    assert pred["p2_35d_first_canonical_repo_commit"] == (
        "38e3c51cb68af8783904637078b80c756207b0e3"
    )
    assert pred["p2_35d_first_canonical_failure_stage"] == (
        "TIMING_ANCHOR_TIMESTAMP_PARSE_IMPORT"
    )
    assert pred["p2_35d_first_canonical_exception"] == (
        "ModuleNotFoundError: No module named 'breachscope'"
    )
    assert pred["p2_35d_duplicate_execution_count"] == 1
    assert pred["p2_35d_protocol_violation_detected"] is True
    assert pred["p2_35d_first_execution_remains_canonical"] is True
    assert pred["selected_windows_member_decoded_before_this_contract"] is False
    assert pred["selected_windows_json_rows_parsed_before_this_contract"] is False
    assert pred["breachscope_detection_executed_before_this_contract"] is False
    assert pred["breachscope_correlation_executed_before_this_contract"] is False
    assert pred["breachscope_scenario_inference_executed_before_this_contract"] is False
    assert pred["p2_35d_must_remain_immutable"] is True


def test_p2_35e_runner_is_new_analysis_id_and_byte_frozen() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-35e-socbed-acsac2021-timeline-one-pass-v1"
    assert row["runner"]["path"] == "scripts/p2_35e_socbed_timeline_one_pass.py"
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "bffd71419b11ad6e2ac1032ccfe904d7844e3a3a9f6159d6d9e7adeeeb83fca3"
    )
    module = _module()
    assert module.ANALYSIS_ID == "p2-35e-socbed-acsac2021-timeline-one-pass-v1"
    assert module.SCHEMA == "breachscope.p2_35e_socbed_timeline_one_pass.v1"


def test_p2_35e_repo_import_bootstrap_works_outside_repository(tmp_path: Path) -> None:
    code = f"""
import importlib.util
import os
import sys
from pathlib import Path
repo = Path(r"{ROOT}")
runner = Path(r"{RUNNER}")
os.chdir(r"{tmp_path}")
sys.path[:] = [x for x in sys.path if x and Path(x).resolve() != repo.resolve()]
spec = importlib.util.spec_from_file_location("p2_35e_external", runner)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
print(m._parse_timestamp("2021-06-18T14:48:50.260264+02:00").isoformat())
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "2021-06-18T12:48:50.260264+00:00"


def test_p2_35e_global_lock_is_analysis_wide_and_second_acquisition_fails(
    tmp_path: Path,
) -> None:
    row = _load()
    runner = row["runner"]
    assert runner["global_lock_file"] == "external_baseline/locks/P2_35E_ONE_PASS.lock"
    assert runner["global_lock_scope"] == "ANALYSIS_ID_REPOSITORY_GLOBAL"
    assert runner["global_lock_created_with_o_excl"] is True
    assert runner["global_lock_acquired_before_output_directory_creation"] is True

    lock_rel = Path(runner["global_lock_file"])
    assert not lock_rel.is_absolute()
    assert ".." not in lock_rel.parts

    module = _module()
    lock = tmp_path / "P2_35E_ONE_PASS.lock"
    module.acquire_global_lock(lock)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    assert payload["analysis_id"] == "p2-35e-socbed-acsac2021-timeline-one-pass-v1"
    with pytest.raises(RuntimeError, match="already permanently locked"):
        module.acquire_global_lock(lock)


def test_p2_35e_quoted_timing_parser_and_exact_order_are_unchanged() -> None:
    module = _module()
    attacks = list(_load()["timeline"]["expected_attack_order"])
    quoted = module.parse_attackconsole_timeline(_timeline_lines(attacks, True), attacks)
    unquoted = module.parse_attackconsole_timeline(_timeline_lines(attacks, False), attacks)
    assert [row["attack"] for row in quoted] == attacks
    assert [row["attack"] for row in unquoted] == attacks

    wrong = list(attacks)
    wrong[0], wrong[1] = wrong[1], wrong[0]
    with pytest.raises(RuntimeError, match="attackconsole run_attack order mismatch"):
        module.parse_attackconsole_timeline(_timeline_lines(wrong, True), attacks)


def test_p2_35e_adapter_mapping_remains_unchanged_on_synthetic_row() -> None:
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


def test_p2_35e_correction_scope_is_evaluator_only() -> None:
    row = _load()
    correction = row["evaluator_correction"]
    assert correction["scope"] == "EVALUATOR_RUNNER_ONLY"
    assert correction["previous_runner_sha256"] == (
        "892babc03a073a151bdede33561740595dd1cf0821c2e838eb762b4ea6979a72"
    )
    assert correction["new_runner_sha256"] == _sha256(RUNNER)
    assert correction["repository_import_bootstrap"][
        "repo_root_inserted_into_sys_path_before_breachscope_imports"
    ] is True
    lock = correction["analysis_id_global_lock"]
    assert lock["previous_scope"] == "PER_OUTPUT_DIRECTORY"
    assert lock["new_scope"] == "ANALYSIS_ID_REPOSITORY_GLOBAL"
    assert lock["second_acquisition_must_fail"] is True
    assert correction["quoted_timing_parser_unchanged"] is True
    assert correction["adapter_mapping_unchanged"] is True
    assert correction["attack_order_unchanged"] is True
    assert correction["temporal_window_definition_unchanged"] is True
    assert correction["measurement_outputs_unchanged"] is True
    assert correction["claim_boundaries_unchanged"] is True
    assert correction["product_code_changed"] is False
    assert correction["rules_changed"] is False


def test_p2_35e_protocol_and_claim_boundaries_remain_fail_closed() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol[
        "contract_must_merge_before_selected_jsonl_decoding_or_breachscope_execution"
    ] is True
    assert protocol["permanent_analysis_id_global_lock_required"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol[
        "first_lock_acquired_completed_or_failed_execution_is_canonical"
    ] is True
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["p2_35d_analysis_id_must_not_be_reused"] is True
    assert protocol["p2_35d_artifacts_must_remain_immutable"] is True
    assert protocol[
        "selected_jsonl_content_driven_tuning_before_p2_35e_canonical_allowed"
    ] is False
    assert protocol["global_lock_survives_completed_or_failed_execution"] is True

    claim = row["claim_boundary"]
    assert claim["source_attack_invocation_order"] == (
        "KNOWN_FROM_PRIOR_TIMING_LOG_OBSERVATION_NOT_YET_P2_35E_MEASURED"
    )
    assert claim["temporal_window_occupancy"] == "NOT_YET_MEASURED_BY_P2_35E"
    assert claim["attack_step_semantic_attribution"] == "NOT_EVALUATED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["chain_precision"] == "NOT_EVALUATED"
    assert claim["chain_recall"] == "NOT_EVALUATED"
    assert claim["scenario_precision"] == "NOT_EVALUATED"
    assert claim["scenario_recall"] == "NOT_EVALUATED"
    assert claim["production_reconstruction_quality"] == "NOT_CLAIMED"

    p2_35d = yaml.safe_load(P2_35D_FAILURE.read_text(encoding="utf-8"))
    assert p2_35d["protocol"]["same_analysis_id_retry_allowed"] is False
    assert p2_35d["next_step"]["id"] == "P2-35E"
    assert p2_35d["next_step"]["p2_35d_must_remain_immutable"] is True
