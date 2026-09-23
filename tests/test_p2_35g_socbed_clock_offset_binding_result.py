from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "p2_35g_socbed_clock_offset_binding_result.yaml"
RAW = ROOT / "external_baseline" / "results" / "p2_35g_b2e163d" / "result.json"
LOCK = ROOT / "external_baseline" / "locks" / "P2_35G_ONE_PASS.lock"
CONTRACT = ROOT / "external_baseline" / "p2_35g_socbed_clock_offset_binding_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35g_socbed_clock_offset_binding.py"
P2_35F = ROOT / "external_baseline" / "p2_35f_socbed_source_oracle_result.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_35g_canonical_artifacts_are_byte_exact() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == (
        "b2e163d88c9b8c122b27daaa0ed48848091bff96"
    )
    assert row["canonical_repo_commit"] == (
        "b2e163d88c9b8c122b27daaa0ed48848091bff96"
    )
    assert RAW.stat().st_size == 15_021
    assert LOCK.stat().st_size == 107
    assert _sha256(RAW) == (
        "c140485666c02de8ff0dd60282c9a761c4b9829c9dad09dc24b83fdcd28052df"
    )
    assert _sha256(LOCK) == (
        "a56017170d2cecf4bdf298b5849d9d25ccc172a0bb0b4dc144360973089ddb89"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert (
        row["canonical_artifacts"]["permanent_global_lock"]["sha256"]
        == _sha256(LOCK)
    )


def test_p2_35g_raw_result_completed_with_frozen_inputs() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["analysis_id"] == "p2-35g-socbed-clock-offset-binding-v1"
    assert raw["contract_sha256"] == _sha256(CONTRACT)
    assert raw["runner_sha256"] == _sha256(RUNNER)
    assert raw["contract_sha256"] == (
        "9c9bac5337e5cb06a7179c6c03390a5878eae01873f2dcbd25282299ad3c1d11"
    )
    assert raw["runner_sha256"] == (
        "7b05bbda83ac99de02ef83e083accf69a85814d8da79928066616a48e8570c43"
    )
    assert raw["product"]["baseline_repo_commit"] == (
        "3ca80865477cccfa5e967f549acf32d92182eccd"
    )
    assert raw["product"]["breachscope_and_rules_match_frozen_commit"] is True


def test_p2_35g_posthoc_known_event_counts_are_exactly_preserved() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    m = raw["measurement"]
    assert m["raw_jsonl_rows"] == 9_370
    assert m["events"] == 9_369
    assert m["findings"] == 29
    assert m["evaluated_action_count"] == 3
    assert m["actions_with_oracle_telemetry"] == 3
    assert m["oracle_event_count"] == 18

    oracle = m["oracle_results"]
    assert oracle["misc_download_malware"]["known_posthoc_predicate_match_count"] == 15
    assert oracle["misc_download_malware"]["oracle_event_count"] == 15
    assert oracle["misc_set_autostart"]["known_posthoc_predicate_match_count"] == 2
    assert oracle["misc_set_autostart"]["oracle_event_count"] == 2
    assert oracle["misc_execute_malware"]["known_posthoc_predicate_match_count"] == 1
    assert oracle["misc_execute_malware"]["oracle_event_count"] == 1


def test_p2_35g_download_binding_is_fifteen_of_fifteen() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = raw["measurement"]["oracle_results"]["misc_download_malware"]
    assert row["oracle_event_count"] == 15
    assert row["oracle_event_finding_bound_count"] == 15
    assert row["finding_count_on_oracle_events"] == 15
    assert row["finding_rule_ids_on_oracle_events"] == ["R-DL"]
    assert row["finding_techniques_on_oracle_events"] == ["T1105"]
    assert row["any_finding_bound_to_oracle_event"] is True


def test_p2_35g_autostart_binding_gap_is_zero_of_two_exact_events() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = raw["measurement"]["oracle_results"]["misc_set_autostart"]
    assert row["oracle_event_count"] == 2
    assert row["oracle_event_finding_bound_count"] == 0
    assert row["finding_count_on_oracle_events"] == 0
    assert row["finding_rule_ids_on_oracle_events"] == []
    assert row["finding_techniques_on_oracle_events"] == []
    assert row["any_finding_bound_to_oracle_event"] is False
    assert {event["event_id"] for event in row["oracle_events"]} == {"1", "13"}
    assert {event["event_record_id"] for event in row["oracle_events"]} == {
        "1968",
        "1970",
    }


def test_p2_35g_execute_binding_gap_is_zero_of_one_exact_event() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = raw["measurement"]["oracle_results"]["misc_execute_malware"]
    assert row["oracle_event_count"] == 1
    assert row["oracle_event_finding_bound_count"] == 0
    assert row["finding_count_on_oracle_events"] == 0
    assert row["finding_rule_ids_on_oracle_events"] == []
    assert row["finding_techniques_on_oracle_events"] == []
    assert row["any_finding_bound_to_oracle_event"] is False
    event = row["oracle_events"][0]
    assert event["timestamp"] == "2021-06-18T13:09:49.103Z"
    assert event["event_id"] == "1"
    assert event["event_record_id"] == "2008"
    assert event["command_line"] == '"C:\\Windows\\meterpreter_bind_tcp.exe"'


def test_p2_35g_result_records_specific_binding_gaps_without_recall_claim() -> None:
    row = _load()
    decision = row["decision"]
    assert decision["posthoc_known_events_total"] == 18
    assert decision["posthoc_known_events_with_findings"] == 15
    assert decision["misc_download_malware"] == (
        "15_OF_15_EVENTS_BOUND_TO_R_DL_T1105"
    )
    assert decision["misc_set_autostart"] == "0_OF_2_EVENTS_WITH_FINDINGS"
    assert decision["misc_execute_malware"] == "0_OF_1_EVENTS_WITH_FINDINGS"
    assert decision["specific_frozen_binding_gap_observed"] == {
        "misc_set_autostart": True,
        "misc_execute_malware": True,
    }
    assert decision["attack_recall_claim_authorized"] is False
    assert decision["precision_or_recall_claim_authorized"] is False
    assert decision["general_detection_accuracy_claim_authorized"] is False

    claim = row["claim_boundary"]
    assert claim["source_derived_oracle_event_binding"] == (
        "MEASURED_FOR_POSTHOC_KNOWN_EVENT_SET"
    )
    assert claim["telemetry_predicate_match_counts"] == (
        "KNOWN_POSTHOC_BEFORE_CONTRACT"
    )
    assert claim["attack_level_precision"] == "NOT_EVALUATED"
    assert claim["attack_level_recall"] == "NOT_EVALUATED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["eight_attack_recall"] == "NOT_EVALUATED"
    assert claim["general_detection_accuracy"] == "NOT_CLAIMED"


def test_p2_35g_protocol_is_one_pass_and_preserves_p2_35f() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["permanent_analysis_id_global_lock_used"] is True
    assert protocol["first_lock_acquired_execution_retained_as_canonical"] is True
    assert protocol["duplicate_p2_35g_canonical_execution_performed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert protocol["product_or_rules_modified_after_canonical"] is False
    assert protocol["p2_35f_artifacts_modified"] is False
    assert protocol["raw_canonical_result_modified"] is False

    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    assert lock["analysis_id"] == "p2-35g-socbed-clock-offset-binding-v1"

    predecessor = yaml.safe_load(P2_35F.read_text(encoding="utf-8"))
    assert predecessor["status"] == "COMPLETED"
    assert predecessor["contract_merge_commit"] == (
        "8270c8417b2d0df54666234ed1d05c0981d094e1"
    )


def test_p2_35g_global_lock_is_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "external_baseline/locks/P2_35G_ONE_PASS.lock -text -whitespace"
        in attrs
    )
