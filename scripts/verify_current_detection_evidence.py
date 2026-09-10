#!/usr/bin/env python3
"""Verify P2-09E/P2-10 remediation evidence plus calibration transitions."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

import verify_current_detection_evidence_legacy as legacy


CHAIN_SCHEMA = legacy.CHAIN_SCHEMA
DEFAULT_CHAIN = legacy.DEFAULT_CHAIN
CurrentEvidenceError = legacy.CurrentEvidenceError

P2_11D_ID = "p2-11d-local-account-4720"
P2_11D_SCHEMA = "breachscope.p2_11d_external_calibration_measurement.v1"
P2_11D_OUTCOMES = {
    "T1003-1": "miss",
    "T1003-2": "miss",
    "T1006-1": "miss",
    "T1027-2": "miss",
    "T1007-1": "miss",
    "T1007-2": "miss",
    "T1021.001-1": "miss",
    "T1021.001-2": "miss",
    "T1047-1": "miss",
    "T1047-2": "miss",
    "T1136.001-4": "hit",
    "T1136.001-5": "hit",
}

P2_11E_ID = "p2-11e-t1007-service-discovery"
P2_11E_SCHEMA = "breachscope.p2_11e_external_calibration_measurement.v1"
P2_11E_OUTCOMES = {
    "T1003-1": "miss",
    "T1003-2": "miss",
    "T1006-1": "miss",
    "T1027-2": "miss",
    "T1007-1": "hit",
    "T1007-2": "hit",
    "T1021.001-1": "miss",
    "T1021.001-2": "miss",
    "T1047-1": "miss",
    "T1047-2": "miss",
    "T1136.001-4": "hit",
    "T1136.001-5": "hit",
}


def _require(actual: Any, expected: Any, label: str) -> None:
    legacy._require(actual, expected, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    return legacy._mapping(value, label)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _require_sha256(value: Any, label: str) -> str:
    text = str(value or "")
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text.casefold()):
        raise CurrentEvidenceError(f"{label} must be a full SHA-256")
    return text


def _require_positive(value: Any, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CurrentEvidenceError(f"{label} must be a positive integer") from exc
    if parsed <= 0:
        raise CurrentEvidenceError(f"{label} must be a positive integer")
    return parsed


def _verify_live_p2_11d_rule(repo: Path, change: Mapping[str, Any]) -> None:
    rule_file = str(change.get("rule_file") or "")
    _require(rule_file, "rules/p2_11_calibration_rules.yml", "P2-11D rule file")
    _require(change.get("rule_id"), "R-LOCAL-ACCOUNT-4720-NONSYSTEM", "P2-11D rule id")
    _require(change.get("mitre_technique"), "T1136.001", "P2-11D technique")

    rule = legacy._load_rule(repo, rule_file, "R-LOCAL-ACCOUNT-4720-NONSYSTEM")
    _require(rule.get("field"), "event_id", "live P2-11D rule field")
    _require(rule.get("operator"), "equals", "live P2-11D rule operator")
    _require(str(rule.get("pattern")), "4720", "live P2-11D rule pattern")
    _require(rule.get("severity"), "medium", "live P2-11D severity")
    _require(rule.get("mitre_technique"), "T1136.001", "live P2-11D technique")

    expected_conditions = {
        "source": ("equals", "Microsoft-Windows-Security-Auditing"),
        "SubjectUserSid": ("regex", "^(?!S-1-5-18$).+"),
        "TargetDomainName": ("equals_field", "host"),
    }
    for field, (operator, pattern) in expected_conditions.items():
        condition = legacy._condition(rule, field)
        _require(condition.get("operator"), operator, f"live P2-11D {field} operator")
        _require(str(condition.get("pattern")), pattern, f"live P2-11D {field} pattern")

    predicate = _mapping(change.get("predicate"), "P2-11D predicate")
    _require(predicate.get("event_id_equals"), "4720", "P2-11D predicate event id")
    _require(
        predicate.get("source_equals"),
        "Microsoft-Windows-Security-Auditing",
        "P2-11D predicate source",
    )
    _require(
        predicate.get("SubjectUserSid_regex"),
        "^(?!S-1-5-18$).+",
        "P2-11D predicate subject SID",
    )
    _require(
        predicate.get("TargetDomainName_equals_field"),
        "host",
        "P2-11D predicate target domain",
    )

    _require(
        str(change.get("rule_file_git_blob_sha1") or ""),
        "5bb8f41b3d3a46bafac945611825fb744164a5cb",
        "recorded P2-11D historical rule file blob",
    )


def _verify_p2_11d_calibration(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    previous_rule_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "P2-11D"
    _require(record.get("schema"), P2_11D_SCHEMA, f"{label} schema")
    _require(record.get("calibration_id"), P2_11D_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("from_rules_tree_sha256"), previous_rule_hash, f"{label} from rule hash")
    to_hash = _require_sha256(record.get("to_rules_tree_sha256"), f"{label} to rule hash")

    _verify_live_p2_11d_rule(repo, _mapping(record.get("rule_change"), f"{label} rule change"))

    engine = _mapping(record.get("engine_change"), f"{label} engine change")
    _require(engine.get("operator"), "equals_field", f"{label} engine operator")
    _require(engine.get("scope"), "all_of_only", f"{label} engine scope")
    _require(engine.get("missing_fields_fail_closed"), True, f"{label} missing fields")
    _require(engine.get("host_short_name_alias"), True, f"{label} host alias")
    module_path = legacy._relative_file(repo, engine.get("module_file"), f"{label} engine module")
    _require(
        legacy._git_blob_sha1(module_path),
        engine.get("module_git_blob_sha1"),
        f"live {label} engine module blob",
    )
    init_path = legacy._relative_file(repo, engine.get("initializer_file"), f"{label} initializer")
    _require(
        legacy._git_blob_sha1(init_path),
        engine.get("initializer_git_blob_sha1"),
        f"live {label} initializer blob",
    )

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign proof")
    _require(benign.get("baseline_id"), "p2-09d-nextron-win10-v1", f"{label} benign baseline")
    _require(
        benign.get("corpus_sha256"),
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e",
        f"{label} benign corpus hash",
    )
    for key, expected in {
        "evtx_files": 352,
        "non_sysmon_evtx_files": 351,
        "non_sysmon_events": 34423,
        "security_4720_events": 3,
        "security_4720_system_creator_events": 3,
        "exact_predicate_matches": 0,
        "parse_errors": 0,
    }.items():
        _require(int(benign.get(key, -1)), expected, f"{label} benign {key}")
    _require_positive(benign.get("probe_run_id"), f"{label} benign probe run id")
    _require_positive(benign.get("artifact_id"), f"{label} benign artifact id")
    _require_sha256(benign.get("artifact_digest_sha256"), f"{label} benign artifact digest")

    calibration = _mapping(record.get("external_calibration"), f"{label} calibration")
    _require(calibration.get("source_repository"), "arniki/atomic-evtx", f"{label} source repo")
    _require(
        calibration.get("source_commit"),
        "8de5fa8f158b4d72d1e3c6f07053162c90ee6238",
        f"{label} source commit",
    )
    _require(
        calibration.get("selection_frozen_commit"),
        "7541214400507afddca40a22f2adb22504fc3946",
        f"{label} selection commit",
    )
    for key, expected in {
        "before_scenario_hits": 0,
        "after_scenario_hits": 2,
        "scenario_misses": 10,
        "scenario_total": 12,
        "events": 902,
        "rules": 61,
        "findings": 84,
        "flagged_events": 80,
    }.items():
        _require(int(calibration.get(key, -1)), expected, f"{label} calibration {key}")
    _require(
        calibration.get("changed_scenarios"),
        ["T1136.001-4", "T1136.001-5"],
        f"{label} changed scenarios",
    )

    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    _require_positive(execution.get("github_actions_run_id"), f"{label} GitHub Actions run id")
    _require_positive(execution.get("artifact_id"), f"{label} artifact id")
    _require_sha256(execution.get("artifact_digest_sha256"), f"{label} artifact digest")

    aggregate_path = legacy._relative_file(repo, execution.get("aggregate_result"), f"{label} aggregate result")
    _require(_sha256(aggregate_path), execution.get("aggregate_result_sha256"), f"{label} aggregate SHA-256")
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    if not isinstance(aggregate, dict):
        raise CurrentEvidenceError(f"{label} aggregate result must be a mapping")
    _require(aggregate.get("schema"), "breachscope.p2_11d_external_calibration_result.v1", f"{label} aggregate schema")
    _require(aggregate.get("evaluation_class"), "external_calibration", f"{label} aggregate class")
    _require(aggregate.get("detector_repo_commit"), record.get("measurement_repo_commit"), f"{label} detector commit")
    _require(aggregate.get("rules_tree_sha256"), to_hash, f"{label} aggregate rule hash")
    for key, expected in {
        "rules": 61,
        "events": 902,
        "scenario_hits": 2,
        "scenario_misses": 10,
        "findings": 84,
        "flagged_events": 80,
    }.items():
        _require(int(aggregate.get(key, -1)), expected, f"{label} aggregate {key}")
    outcomes = aggregate.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != 12:
        raise CurrentEvidenceError(f"{label} aggregate must contain 12 outcomes")
    observed = {
        str(row.get("scenario_id")): str(row.get("status"))
        for row in outcomes
        if isinstance(row, Mapping)
    }
    _require(observed, P2_11D_OUTCOMES, f"{label} outcome map")
    event_level = _mapping(aggregate.get("event_level"), f"{label} event-level boundary")
    _require(event_level.get("labels"), "all_ignore", f"{label} event labels")
    _require(int(event_level.get("scored_events", -1)), 0, f"{label} scored events")
    for key in ("precision", "recall", "false_positive_rate"):
        _require(event_level.get(key), "NOT_CLAIMED", f"{label} {key} boundary")

    claims = _mapping(record.get("claim_boundary"), f"{label} claim boundary")
    _require(claims.get("final_blind_holdout"), False, f"{label} final blind holdout")
    _require(claims.get("fresh_external_baseline"), False, f"{label} fresh baseline")
    _require(claims.get("production_detection_rate"), "NOT_CLAIMED", f"{label} production detection")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} production FPR")
    _require(claims.get("fresh_full_benign_fpr_for_new_rulepack"), "NOT_CLAIMED", f"{label} fresh benign FPR")

    return to_hash, {
        "calibration_id": P2_11D_ID,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_rule_hash,
        "to_rules_tree_sha256": to_hash,
        "scenario_hits_before": 0,
        "scenario_hits_after": 2,
        "scenario_total": 12,
        "events": 902,
        "rules": 61,
        "findings": 84,
        "flagged_events": 80,
        "benign_events_scanned": 34423,
        "benign_exact_predicate_matches": 0,
        "record_path": record_path.relative_to(repo).as_posix(),
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def _verify_live_p2_11e_rules(repo: Path, change: Mapping[str, Any]) -> None:
    label = "P2-11E"
    rule_file = str(change.get("rule_file") or "")
    _require(rule_file, "rules/p2_11_calibration_rules.yml", f"{label} rule file")
    rules = change.get("rules")
    if not isinstance(rules, list) or len(rules) != 2:
        raise CurrentEvidenceError(f"{label} must record exactly two rule changes")
    recorded = {
        str(row.get("rule_id")): row
        for row in rules
        if isinstance(row, Mapping)
    }
    _require(
        set(recorded),
        {"R-SERVICE-DISCOVERY-SC-LIST", "R-SERVICE-DISCOVERY-NET-START-LIST"},
        f"{label} rule ids",
    )

    expected = {
        "R-SERVICE-DISCOVERY-SC-LIST": {
            "field": "Image",
            "operator": "endswith",
            "pattern": r"\sc.exe",
            "severity": "low",
            "command_line": r'\bsc(?:\.exe)?"?\s+query(?:\s+state\s*=\s*all)?\s*$',
        },
        "R-SERVICE-DISCOVERY-NET-START-LIST": {
            "field": "Image",
            "operator": "regex",
            "pattern": r"\\net1?\.exe$",
            "severity": "low",
            "command_line": r'\bnet1?(?:\.exe)?"?\s+start\s*$',
        },
    }
    for rule_id, spec in expected.items():
        row = recorded[rule_id]
        _require(row.get("mitre_technique"), "T1007", f"{label} {rule_id} recorded technique")
        rule = legacy._load_rule(repo, rule_file, rule_id)
        _require(rule.get("field"), spec["field"], f"live {label} {rule_id} field")
        _require(rule.get("operator"), spec["operator"], f"live {label} {rule_id} operator")
        _require(str(rule.get("pattern")), spec["pattern"], f"live {label} {rule_id} pattern")
        _require(rule.get("severity"), spec["severity"], f"live {label} {rule_id} severity")
        _require(rule.get("mitre_technique"), "T1007", f"live {label} {rule_id} technique")
        for field, operator, pattern in (
            ("source", "equals", "Microsoft-Windows-Sysmon"),
            ("event_id", "equals", "1"),
            ("command_line", "regex", spec["command_line"]),
        ):
            condition = legacy._condition(rule, field)
            _require(condition.get("operator"), operator, f"live {label} {rule_id} {field} operator")
            _require(str(condition.get("pattern")), pattern, f"live {label} {rule_id} {field} pattern")

    _require(
        legacy._git_blob_sha1(repo / rule_file),
        str(change.get("rule_file_git_blob_sha1") or ""),
        f"live {label} rule file blob",
    )


def _verify_p2_11e_calibration(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    previous_rule_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "P2-11E"
    _require(record.get("schema"), P2_11E_SCHEMA, f"{label} schema")
    _require(record.get("calibration_id"), P2_11E_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("from_rules_tree_sha256"), previous_rule_hash, f"{label} from rule hash")
    to_hash = _require_sha256(record.get("to_rules_tree_sha256"), f"{label} to rule hash")
    _require(
        record.get("measurement_repo_commit"),
        "aa08c6beca2720a69165aed37562ba9730a8a62f",
        f"{label} detector commit",
    )

    _verify_live_p2_11e_rules(repo, _mapping(record.get("rule_change"), f"{label} rule change"))

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign proof")
    _require(benign.get("baseline_id"), "p2-09d-nextron-win10-v1", f"{label} benign baseline")
    _require(
        benign.get("corpus_sha256"),
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e",
        f"{label} benign corpus hash",
    )
    for key, expected in {
        "sysmon_records": 732200,
        "sysmon_chunks": 11894,
        "sysmon_event1": 2149,
        "sc_exe_event1": 4,
        "net_exe_event1": 0,
        "net1_exe_event1": 0,
        "sc_query_list_exact": 0,
        "net_start_list_exact": 0,
        "parse_errors": 0,
    }.items():
        _require(int(benign.get(key, -1)), expected, f"{label} benign {key}")
    _require_positive(benign.get("probe_run_id"), f"{label} benign probe run id")
    _require_positive(benign.get("artifact_id"), f"{label} benign artifact id")
    _require_sha256(benign.get("artifact_digest_sha256"), f"{label} benign artifact digest")
    _require(benign.get("fresh_full_fp_tn_rerun"), False, f"{label} benign fresh full rerun")

    stored_path = legacy._relative_file(repo, benign.get("stored_result"), f"{label} benign stored result")
    _require(_sha256(stored_path), benign.get("stored_result_sha256"), f"{label} benign stored SHA-256")
    stored = json.loads(stored_path.read_text(encoding="utf-8"))
    if not isinstance(stored, dict):
        raise CurrentEvidenceError(f"{label} benign stored result must be a mapping")
    _require(stored.get("schema"), "breachscope.p2_11e_t1007_benign_probe.v1", f"{label} benign stored schema")
    _require(stored.get("corpus_sha256"), benign.get("corpus_sha256"), f"{label} benign stored corpus")
    scope = _mapping(stored.get("scope"), f"{label} benign stored scope")
    for key, expected in {
        "sysmon_records": 732200,
        "sysmon_chunks": 11894,
        "sysmon_event1": 2149,
        "parse_errors": 0,
    }.items():
        _require(int(scope.get(key, -1)), expected, f"{label} benign stored {key}")
    process_counts = _mapping(stored.get("process_counts"), f"{label} benign process counts")
    for key, expected in {"sc_exe_event1": 4, "net_exe_event1": 0, "net1_exe_event1": 0}.items():
        _require(int(process_counts.get(key, -1)), expected, f"{label} benign stored {key}")
    candidate_counts = _mapping(stored.get("candidate_counts"), f"{label} benign candidates")
    _require(int(candidate_counts.get("sc_query_list_exact", -1)), 0, f"{label} benign SC candidate")
    _require(int(candidate_counts.get("net_start_list_exact", -1)), 0, f"{label} benign NET candidate")
    stored_claims = _mapping(stored.get("claim_boundary"), f"{label} benign stored claims")
    _require(stored_claims.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} benign stored production FPR")

    calibration = _mapping(record.get("external_calibration"), f"{label} calibration")
    _require(
        calibration.get("previous_measurement_record"),
        "external_baseline/results/p2_11d_456b2a82/measurement.yaml",
        f"{label} previous measurement",
    )
    _require(calibration.get("source_repository"), "arniki/atomic-evtx", f"{label} source repo")
    _require(
        calibration.get("source_commit"),
        "8de5fa8f158b4d72d1e3c6f07053162c90ee6238",
        f"{label} source commit",
    )
    _require(
        calibration.get("selection_frozen_commit"),
        "7541214400507afddca40a22f2adb22504fc3946",
        f"{label} selection commit",
    )
    for key, expected in {
        "before_scenario_hits": 2,
        "after_scenario_hits": 4,
        "scenario_misses": 8,
        "scenario_total": 12,
        "events": 902,
        "rules": 63,
        "findings": 88,
        "flagged_events": 84,
    }.items():
        _require(int(calibration.get(key, -1)), expected, f"{label} calibration {key}")
    _require(calibration.get("changed_scenarios"), ["T1007-1", "T1007-2"], f"{label} changed scenarios")
    _require(
        calibration.get("remaining_miss_scenarios"),
        [
            "T1003-1",
            "T1003-2",
            "T1006-1",
            "T1027-2",
            "T1021.001-1",
            "T1021.001-2",
            "T1047-1",
            "T1047-2",
        ],
        f"{label} remaining misses",
    )

    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    _require(int(execution.get("github_actions_run_id", 0)), 34437094844, f"{label} GitHub Actions run id")
    _require(execution.get("workflow_control_head_commit"), "6581dc1f61f445cc768a688ce5f96b5aa74d99df", f"{label} control head")
    _require(execution.get("detector_repo_commit"), record.get("measurement_repo_commit"), f"{label} execution detector commit")
    _require(int(execution.get("artifact_id", 0)), 10136572099, f"{label} artifact id")
    _require(
        execution.get("artifact_digest_sha256"),
        "329d7c7f8eed02fca7dd9f06b30bf59d20aaf8904484d1a5909452f3bc6e0c1f",
        f"{label} artifact digest",
    )
    _require(
        execution.get("rules_freeze_sha256"),
        "dfbc7c77c5ccf775428e1ce00edd997aad873969273ba7410faf03e09f0d1a5c",
        f"{label} rules freeze SHA-256",
    )
    _require(int(execution.get("freeze_probe_run_id", 0)), 34436963895, f"{label} freeze probe run id")
    _require(int(execution.get("freeze_probe_artifact_id", 0)), 10136515911, f"{label} freeze probe artifact id")
    _require(
        execution.get("freeze_probe_artifact_digest_sha256"),
        "d7b7d1281302667815d04d79e88e7b890ee309768f9a950db62e44b172e66c71",
        f"{label} freeze probe artifact digest",
    )

    aggregate_path = legacy._relative_file(repo, execution.get("aggregate_result"), f"{label} aggregate result")
    _require(_sha256(aggregate_path), execution.get("aggregate_result_sha256"), f"{label} aggregate SHA-256")
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    if not isinstance(aggregate, dict):
        raise CurrentEvidenceError(f"{label} aggregate result must be a mapping")
    _require(aggregate.get("schema"), "breachscope.p2_11e_external_calibration_result.v1", f"{label} aggregate schema")
    _require(aggregate.get("evaluation_class"), "external_calibration", f"{label} aggregate class")
    _require(aggregate.get("detector_repo_commit"), record.get("measurement_repo_commit"), f"{label} aggregate detector commit")
    _require(aggregate.get("rules_tree_sha256"), to_hash, f"{label} aggregate rule hash")
    _require(int(aggregate.get("rule_file_count", -1)), 4, f"{label} aggregate rule files")
    for key, expected in {
        "rules": 63,
        "events": 902,
        "scenario_hits": 4,
        "scenario_misses": 8,
        "findings": 88,
        "flagged_events": 84,
    }.items():
        _require(int(aggregate.get(key, -1)), expected, f"{label} aggregate {key}")
    outcomes = aggregate.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != 12:
        raise CurrentEvidenceError(f"{label} aggregate must contain 12 outcomes")
    observed = {
        str(row.get("scenario_id")): str(row.get("status"))
        for row in outcomes
        if isinstance(row, Mapping)
    }
    _require(observed, P2_11E_OUTCOMES, f"{label} outcome map")
    event_level = _mapping(aggregate.get("event_level"), f"{label} event-level boundary")
    _require(event_level.get("labels"), "all_ignore", f"{label} event labels")
    _require(int(event_level.get("scored_events", -1)), 0, f"{label} scored events")
    for key in ("precision", "recall", "false_positive_rate"):
        _require(event_level.get(key), "NOT_CLAIMED", f"{label} {key} boundary")
    aggregate_claims = _mapping(aggregate.get("claim_boundary"), f"{label} aggregate claims")
    _require(aggregate_claims.get("final_blind_holdout"), False, f"{label} aggregate final blind")
    _require(aggregate_claims.get("fresh_external_baseline"), False, f"{label} aggregate fresh baseline")
    for key in (
        "production_detection_rate",
        "production_precision",
        "production_recall",
        "production_false_positive_rate",
    ):
        _require(aggregate_claims.get(key), "NOT_CLAIMED", f"{label} aggregate {key}")

    claims = _mapping(record.get("claim_boundary"), f"{label} claim boundary")
    _require(claims.get("final_blind_holdout"), False, f"{label} final blind holdout")
    _require(claims.get("fresh_external_baseline"), False, f"{label} fresh baseline")
    for key in (
        "production_detection_rate",
        "production_precision",
        "production_recall",
        "production_false_positive_rate",
        "fresh_full_benign_fpr_for_new_rulepack",
    ):
        _require(claims.get(key), "NOT_CLAIMED", f"{label} {key} boundary")

    return to_hash, {
        "calibration_id": P2_11E_ID,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_rule_hash,
        "to_rules_tree_sha256": to_hash,
        "scenario_hits_before": 2,
        "scenario_hits_after": 4,
        "scenario_total": 12,
        "events": 902,
        "rules": 63,
        "findings": 88,
        "flagged_events": 84,
        "benign_events_scanned": 732200,
        "benign_exact_predicate_matches": 0,
        "record_path": record_path.relative_to(repo).as_posix(),
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = legacy._load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    _require(chain.get("current_evidence_id"), "p2-11e-current-detection-evidence", "current evidence id")
    base_path = legacy._relative_file(repo, chain.get("base_benchmark"), "base benchmark")
    base = legacy._verify_base_benchmark(repo, base_path)
    _require(chain.get("base_rules_tree_sha256"), base["rules_tree_sha256"], "current evidence base rule hash")

    previous_rule_hash = str(base["rules_tree_sha256"])
    previous_attack_hits = int(base["attack"]["scenario_hits"])
    verified_remediations: list[dict[str, Any]] = []
    remediations = chain.get("remediations")
    if not isinstance(remediations, list):
        raise CurrentEvidenceError("remediations must be a list")

    ordered_ids: list[str] = []
    seen_ids: set[str] = set()
    for item in remediations:
        if not isinstance(item, Mapping):
            raise CurrentEvidenceError("each remediation chain item must be a mapping")
        remediation_id = str(item.get("remediation_id") or "")
        if not remediation_id or remediation_id in seen_ids:
            raise CurrentEvidenceError("remediation_id values must be non-empty and unique")
        seen_ids.add(remediation_id)
        ordered_ids.append(remediation_id)
        record_path = legacy._relative_file(repo, item.get("measurement_record"), f"{remediation_id} measurement record")
        record = legacy._load_yaml(record_path)
        previous_rule_hash, previous_attack_hits, verified = legacy._verify_record(
            repo,
            record_path,
            record,
            remediation_id,
            previous_rule_hash,
            base,
            previous_attack_hits,
        )
        verified_remediations.append(verified)
    _require(ordered_ids, list(legacy.SPECS), "remediation chain order/content")

    calibrations = chain.get("calibrations")
    if not isinstance(calibrations, list):
        raise CurrentEvidenceError("calibrations must be a list")
    calibration_ids = [
        str(row.get("calibration_id") or "")
        for row in calibrations
        if isinstance(row, Mapping)
    ]
    _require(calibration_ids, [P2_11D_ID, P2_11E_ID], "calibration chain order/content")

    verified_calibrations: list[dict[str, Any]] = []
    for item in calibrations:
        calibration_id = str(item.get("calibration_id") or "")
        record_path = legacy._relative_file(repo, item.get("measurement_record"), f"{calibration_id} measurement record")
        record = legacy._load_yaml(record_path)
        if calibration_id == P2_11D_ID:
            previous_rule_hash, verified = _verify_p2_11d_calibration(
                repo, record_path, record, previous_rule_hash
            )
        elif calibration_id == P2_11E_ID:
            previous_rule_hash, verified = _verify_p2_11e_calibration(
                repo, record_path, record, previous_rule_hash
            )
        else:
            raise CurrentEvidenceError(f"unsupported calibration: {calibration_id}")
        verified_calibrations.append(verified)

    current_rule_hash, rule_file_count = legacy.historical._rules_tree_hash(repo / "rules")
    _require(previous_rule_hash, current_rule_hash, "current rule tree explained by remediation/calibration chain")

    claims = _mapping(chain.get("claim_boundary"), "current evidence claim boundary")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", "current production accuracy boundary")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", "current production FPR boundary")
    _require(claims.get("final_blind_holdout"), False, "current final blind holdout boundary")
    _require(
        claims.get("fresh_full_benign_fpr_for_current_rulepack"),
        "NOT_CLAIMED",
        "current fresh benign FPR boundary",
    )

    return {
        "schema": "breachscope.current_detection_evidence_verification.v3",
        "current_evidence_id": chain.get("current_evidence_id"),
        "status": "PASS",
        "base_rules_tree_sha256": base["rules_tree_sha256"],
        "current_rules_tree_sha256": current_rule_hash,
        "rule_file_count": rule_file_count,
        "base_attack_scenario_hits": int(base["attack"]["scenario_hits"]),
        "current_attack_scenario_hits": previous_attack_hits,
        "attack_scenario_total": int(base["attack"]["scenario_total"]),
        "historical_benign": {
            "events": int(base["benign"]["events"]),
            "false_positives": int(base["benign"]["false_positives"]),
            "true_negatives": int(base["benign"]["true_negatives"]),
            "false_positive_rate": float(base["benign"]["false_positive_rate"]),
            "applies_to_rules_tree_sha256": base["rules_tree_sha256"],
        },
        "remediations": verified_remediations,
        "calibrations": verified_calibrations,
        "claim_boundary": {
            "production_accuracy": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "fresh_full_benign_fpr_for_current_rulepack": "NOT_CLAIMED",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain", default=DEFAULT_CHAIN)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    try:
        chain_path = legacy._relative_file(repo, args.chain, "current evidence chain")
        result = verify(repo, chain_path)
    except (
        CurrentEvidenceError,
        legacy.historical.BenchmarkError,
        OSError,
        yaml.YAMLError,
        json.JSONDecodeError,
    ) as exc:
        print(f"Current detection evidence verification: FAIL: {exc}")
        return 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print("Current detection evidence verification: PASS")
        print(f"Base rules SHA-256: {result['base_rules_tree_sha256']}")
        print(f"Current rules SHA-256: {result['current_rules_tree_sha256']}")
        print(
            "Historical public attack baseline: "
            f"{result['base_attack_scenario_hits']}/{result['attack_scenario_total']} -> "
            f"{result['current_attack_scenario_hits']}/{result['attack_scenario_total']} scenario hits"
        )
        for calibration in result["calibrations"]:
            print(
                f"{calibration['calibration_id']}: external calibration "
                f"{calibration['scenario_hits_before']}/{calibration['scenario_total']} -> "
                f"{calibration['scenario_hits_after']}/{calibration['scenario_total']} scenario hits"
            )
        print("Fresh full benign FPR for current rulepack: NOT CLAIMED")
        print("Production accuracy/FPR: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
