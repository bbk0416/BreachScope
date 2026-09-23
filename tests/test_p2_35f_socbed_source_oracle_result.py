from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "p2_35f_socbed_source_oracle_result.yaml"
RAW = ROOT / "external_baseline" / "results" / "p2_35f_8270c84" / "result.json"
LOCK = ROOT / "external_baseline" / "locks" / "P2_35F_ONE_PASS.lock"
CONTRACT = ROOT / "external_baseline" / "p2_35f_socbed_source_oracle_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35f_socbed_source_oracle.py"
P2_35E = ROOT / "external_baseline" / "p2_35e_socbed_timeline_one_pass_result.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_p2_35f_canonical_artifacts_are_byte_exact() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == (
        "8270c8417b2d0df54666234ed1d05c0981d094e1"
    )
    assert row["canonical_repo_commit"] == (
        "8270c8417b2d0df54666234ed1d05c0981d094e1"
    )
    assert RAW.stat().st_size == 8_200
    assert LOCK.stat().st_size == 108
    assert _sha256(RAW) == (
        "f68eb1ecaa38a47ffb721ffb89f91c32fe92b57900f71e986e6175a023d0e215"
    )
    assert _sha256(LOCK) == (
        "49e55abd30899c7b25a6d68e7e5d9e1832e085fdd1dad43ef27cba0f32424969"
    )
    assert row["canonical_artifacts"]["result"]["sha256"] == _sha256(RAW)
    assert (
        row["canonical_artifacts"]["permanent_global_lock"]["sha256"]
        == _sha256(LOCK)
    )


def test_p2_35f_raw_result_completed_with_frozen_inputs() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["status"] == "completed"
    assert raw["analysis_id"] == "p2-35f-socbed-source-derived-oracle-v1"
    assert raw["contract_sha256"] == _sha256(CONTRACT)
    assert raw["runner_sha256"] == _sha256(RUNNER)
    assert raw["contract_sha256"] == (
        "35a4a93b316d9321f612861e90aba32d2baba3a0ff13a94da5b432fcdd11924b"
    )
    assert raw["runner_sha256"] == (
        "6010438daef731096045fa4ebb789d09562d0b0a886e2c3ed98f3f965a57eae5"
    )
    assert raw["predecessor_runner_sha256"] == (
        "bffd71419b11ad6e2ac1032ccfe904d7844e3a3a9f6159d6d9e7adeeeb83fca3"
    )
    assert raw["product"]["baseline_repo_commit"] == (
        "3ca80865477cccfa5e967f549acf32d92182eccd"
    )
    assert raw["product"]["breachscope_and_rules_match_frozen_commit"] is True
    assert raw["source"]["archive_sha256"] == (
        "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    )


def test_p2_35f_measurement_seals_one_of_three_frozen_predicates() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    m = raw["measurement"]
    assert m["raw_jsonl_rows"] == 9_370
    assert m["events"] == 9_369
    assert m["findings"] == 29
    assert m["evaluated_action_count"] == 3
    assert m["actions_with_oracle_telemetry"] == 1
    assert m["actions_with_findings_bound_to_oracle_events"] == 1
    assert m["oracle_event_count"] == 5
    assert m["oracle_events_with_findings"] == 5

    oracle = m["oracle_results"]
    dl = oracle["misc_download_malware"]
    assert dl["oracle_event_count"] == 5
    assert dl["oracle_event_finding_bound_count"] == 5
    assert dl["finding_count_on_oracle_events"] == 5
    assert dl["finding_rule_ids_on_oracle_events"] == ["R-DL"]
    assert dl["finding_techniques_on_oracle_events"] == ["T1105"]
    assert dl["action_observable_in_selected_source"] is True
    assert dl["any_finding_bound_to_oracle_event"] is True

    autostart = oracle["misc_set_autostart"]
    assert autostart["oracle_event_count"] == 0
    assert autostart["oracle_event_finding_bound_count"] == 0
    assert autostart["action_observable_in_selected_source"] is False
    assert autostart["any_finding_bound_to_oracle_event"] is False

    execute = oracle["misc_execute_malware"]
    assert execute["oracle_event_count"] == 0
    assert execute["oracle_event_finding_bound_count"] == 0
    assert execute["action_observable_in_selected_source"] is False
    assert execute["any_finding_bound_to_oracle_event"] is False


def test_p2_35f_download_oracle_events_are_exact_and_all_bound() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    rows = raw["measurement"]["oracle_results"]["misc_download_malware"]["oracle_events"]
    assert len(rows) == 5
    assert {row["host"] for row in rows} == {"CLIENT1.breach.local"}
    assert {row["event_id"] for row in rows} == {"403", "800", "4103"}
    assert {row["event_record_id"] for row in rows} == {
        "6028",
        "6029",
        "6030",
        "5525",
        "5526",
    }
    assert all(
        "Invoke-WebRequest" in row["command_line"]
        and "http://172.18.1.1/meterpreter_bind_tcp.exe" in row["command_line"]
        and "C:\\Windows\\meterpreter_bind_tcp.exe" in row["command_line"]
        for row in rows
    )


def test_p2_35f_five_other_socbed_actions_remain_not_evaluated() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    oracle = raw["measurement"]["oracle_results"]
    not_evaluated = {
        name
        for name, row in oracle.items()
        if row["disposition"] != "EVALUATED_SOURCE_DERIVED_ORACLE"
    }
    assert not_evaluated == {
        "misc_sqlmap",
        "infect_email_exe",
        "c2_take_screenshot",
        "c2_exfiltration",
        "c2_mimikatz",
    }
    assert all(
        oracle[name]["disposition"].startswith("NOT_EVALUATED_")
        for name in not_evaluated
    )


def test_p2_35f_raw_claim_boundary_stale_metadata_is_preserved_not_rewritten() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = _load()
    assert raw["claim_boundary"]["source_derived_oracle_event_binding"] == (
        "NOT_YET_MEASURED"
    )
    issue = row["raw_metadata_issue"]
    assert issue["present"] is True
    assert issue["field"] == "claim_boundary.source_derived_oracle_event_binding"
    assert issue["raw_value"] == "NOT_YET_MEASURED"
    assert issue["expected_postmeasurement_state"] == (
        "MEASURED_FOR_THREE_PREREGISTERED_SOURCE_DERIVED_PREDICATES"
    )
    assert issue["canonical_raw_modified"] is False
    assert issue["canonical_rerun_performed"] is False


def test_p2_35f_result_does_not_inflate_predicate_matches_into_recall() -> None:
    row = _load()
    decision = row["decision"]
    assert decision["canonical_execution"] == "COMPLETED"
    assert decision["frozen_predicate_match_actions"] == "1_OF_3"
    assert decision["exact_finding_binding_actions"] == "1_OF_3"
    assert decision["misc_download_malware"] == (
        "PREDICATE_MATCHED_AND_FINDING_BOUND"
    )
    assert decision["misc_set_autostart"] == "NO_MATCH_FOR_PREREGISTERED_PREDICATE"
    assert decision["misc_execute_malware"] == "NO_MATCH_FOR_PREREGISTERED_PREDICATE"
    assert decision["eight_attack_recall_claim_authorized"] is False
    assert decision["precision_or_recall_claim_authorized"] is False
    assert decision["general_detection_accuracy_claim_authorized"] is False

    claim = row["claim_boundary"]
    assert claim["source_derived_oracle_event_binding"] == (
        "MEASURED_FOR_THREE_PREREGISTERED_SOURCE_DERIVED_PREDICATES"
    )
    assert claim["frozen_predicate_match_counts_are_attack_recall"] is False
    assert claim["attack_level_precision"] == "NOT_EVALUATED"
    assert claim["attack_level_recall"] == "NOT_EVALUATED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["eight_attack_recall"] == "NOT_EVALUATED"
    assert claim["general_detection_accuracy"] == "NOT_CLAIMED"


def test_p2_35f_protocol_is_one_pass_and_preserves_p2_35e() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["permanent_analysis_id_global_lock_used"] is True
    assert protocol["first_lock_acquired_execution_retained_as_canonical"] is True
    assert protocol["duplicate_p2_35f_canonical_execution_performed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert protocol["product_or_rules_modified_after_canonical"] is False
    assert protocol["p2_35e_artifacts_modified"] is False
    assert protocol["raw_canonical_result_modified"] is False

    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    assert lock["analysis_id"] == "p2-35f-socbed-source-derived-oracle-v1"

    predecessor = yaml.safe_load(P2_35E.read_text(encoding="utf-8"))
    assert predecessor["status"] == "COMPLETED"
    assert predecessor["contract_merge_commit"] == (
        "e4561e34b5d80a3539c671ebfd3cfeae487b2caf"
    )


def test_p2_35f_global_lock_is_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "external_baseline/locks/P2_35F_ONE_PASS.lock -text -whitespace"
        in attrs
    )
