#!/usr/bin/env python3
"""Verify the historical P2-09E benchmark plus the current remediation chain."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

import verify_reproducible_benchmark as historical


CHAIN_SCHEMA = "breachscope.current_detection_evidence_chain.v1"
DEFAULT_CHAIN = "external_baseline/current_detection_evidence.yaml"


class CurrentEvidenceError(RuntimeError):
    pass


def _require(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise CurrentEvidenceError(f"{label}: expected {expected!r}, got {actual!r}")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CurrentEvidenceError(f"mapping required: {label}")
    return value


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CurrentEvidenceError(f"YAML mapping required: {path}")
    return data


def _relative_file(repo: Path, value: Any, label: str) -> Path:
    try:
        return historical._relative_file(repo, value, label)
    except historical.BenchmarkError as exc:
        raise CurrentEvidenceError(str(exc)) from exc


def _verify_base_benchmark(repo: Path, manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = historical._load_yaml(manifest_path)
        historical._require(manifest.get("schema"), historical.SCHEMA, "benchmark schema")
        historical._require(
            manifest.get("benchmark_type"),
            "detection_evidence_not_performance",
            "benchmark type",
        )
        common = historical._mapping(
            manifest.get("common_detection_contract"), "common_detection_contract"
        )
        base_rule_hash = str(common.get("rules_tree_sha256") or "")
        historical._require(
            common.get("commit_range_detection_semantics_changed"),
            False,
            "commit-range detection semantics boundary",
        )
        components = historical._mapping(manifest.get("components"), "components")
        attack_component = historical._mapping(
            components.get("attack_external_baseline"), "attack component"
        )
        benign_component = historical._mapping(
            components.get("benign_external_baseline"), "benign component"
        )
        attack, attack_files = historical._verify_attack(repo, attack_component, base_rule_hash)
        benign, benign_files = historical._verify_benign(repo, benign_component, base_rule_hash)
        claims = historical._mapping(manifest.get("claim_boundary"), "benchmark claim_boundary")
        historical._require(
            claims.get("production_accuracy"),
            "NOT_CLAIMED",
            "benchmark production accuracy boundary",
        )
        historical._require(
            claims.get("production_false_positive_rate"),
            "NOT_CLAIMED",
            "benchmark production FPR boundary",
        )
        historical._require(
            claims.get("final_blind_holdout"),
            False,
            "benchmark final blind holdout boundary",
        )
        historical._require(
            claims.get("performance_benchmark"),
            "NOT_CLAIMED",
            "benchmark performance boundary",
        )
    except historical.BenchmarkError as exc:
        raise CurrentEvidenceError(f"historical benchmark invalid: {exc}") from exc

    return {
        "rules_tree_sha256": base_rule_hash,
        "attack": attack,
        "benign": benign,
        "attack_result": historical._load_yaml(attack_files[1]),
        "benign_source": historical._load_yaml(benign_files[0]),
    }


def _load_rule(repo: Path, rule_file: str, rule_id: str) -> Mapping[str, Any]:
    path = _relative_file(repo, rule_file, "remediation rule_file")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise CurrentEvidenceError(f"rule file must contain a YAML list: {rule_file}")
    matches = [row for row in data if isinstance(row, Mapping) and row.get("id") == rule_id]
    if len(matches) != 1:
        raise CurrentEvidenceError(
            f"rule {rule_id!r} must appear exactly once in {rule_file}; got {len(matches)}"
        )
    return matches[0]


def _condition(rule: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    all_of = rule.get("all_of")
    if not isinstance(all_of, list):
        raise CurrentEvidenceError("live remediation rule all_of must be a list")
    matches = [row for row in all_of if isinstance(row, Mapping) and row.get("field") == field]
    if len(matches) != 1:
        raise CurrentEvidenceError(
            f"live remediation rule must have exactly one {field!r} condition; got {len(matches)}"
        )
    return matches[0]


def _base_context(base: Mapping[str, Any]) -> tuple[
    Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]
]:
    base_attack = _mapping(base.get("attack"), "base attack")
    base_attack_result = _mapping(base.get("attack_result"), "base attack result")
    base_corpus = _mapping(base_attack_result.get("corpus"), "base attack corpus")
    base_benign = _mapping(base.get("benign"), "base benign")
    benign_source_doc = _mapping(base.get("benign_source"), "base benign source document")
    benign_source = _mapping(benign_source_doc.get("source"), "base benign source")
    return base_attack, base_corpus, base_benign, benign_source


def _verify_claims(record: Mapping[str, Any], label: str) -> None:
    claims = _mapping(record.get("claim_boundary"), f"{label} claim boundary")
    _require(claims.get("final_blind_holdout"), False, f"{label} final blind holdout boundary")
    _require(
        claims.get("production_detection_rate"),
        "NOT_CLAIMED",
        f"{label} production detection boundary",
    )
    _require(
        claims.get("production_false_positive_rate"),
        "NOT_CLAIMED",
        f"{label} production FPR boundary",
    )
    _require(
        claims.get("fresh_full_benign_fpr_for_new_rulepack"),
        "NOT_CLAIMED",
        f"{label} fresh benign FPR boundary",
    )


def _verify_execution(
    record: Mapping[str, Any],
    label: str,
    focused_tests: int,
    artifact_schema: str | None = None,
) -> Mapping[str, Any]:
    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    if int(execution.get("github_actions_run_id", 0)) <= 0:
        raise CurrentEvidenceError(f"{label} GitHub Actions run id is required")
    if int(execution.get("artifact_id", 0)) <= 0:
        raise CurrentEvidenceError(f"{label} artifact id is required")
    digest = str(execution.get("artifact_digest_sha256") or "")
    if len(digest) != 64:
        raise CurrentEvidenceError(f"{label} artifact digest must be a full SHA-256")
    _require(
        int(execution.get("focused_tests_passed", -1)),
        focused_tests,
        f"{label} focused test count",
    )
    if artifact_schema is not None:
        _require(
            execution.get("artifact_record_schema"),
            artifact_schema,
            f"{label} artifact record schema",
        )
    return execution


SPECS: dict[str, dict[str, Any]] = {
    "p2-10a-scheduled-task-4698": {
        "label": "P2-10A",
        "schema": "breachscope.p2_10a_remediation_measurement.v1",
        "rule_id": "R-SCHTASK-4698",
        "technique": "T1053.005",
        "severity": "low",
        "primary": ("event_id", "equals", "4698"),
        "conditions": {
            "source": ("equals", "Microsoft-Windows-Security-Auditing"),
        },
        "predicate": {
            "event_id_equals": "4698",
            "source_equals": "Microsoft-Windows-Security-Auditing",
        },
        "after_hits": 3,
        "misses": 7,
        "findings": 4,
        "changed_scenario": ("exec-scheduled-task", "T1053.005"),
        "focused_tests": 4,
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "non_sysmon_source_files_scanned": 351,
            "non_sysmon_events_scanned": 34423,
            "exact_predicate_matches": 0,
            "sysmon_events_from_p2_09d": 732200,
            "sysmon_provider_disjoint_from_rule_source_predicate": True,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "non-Sysmon events",
            "benign_events_scanned": 34423,
            "benign_non_sysmon_events_scanned": 34423,
            "benign_exact_predicate_matches": 0,
        },
    },
    "p2-10b-wmi-xsl": {
        "label": "P2-10B",
        "schema": "breachscope.p2_10b_remediation_measurement.v1",
        "rule_id": "R-WMI-XSL-Remote",
        "technique": "T1047",
        "severity": "low",
        "primary": ("command_line", "contains", "wmic"),
        "conditions": {
            "command_line": ("contains", '/format:"http'),
            "event_id": ("equals", "1"),
            "source": ("equals", "Microsoft-Windows-Sysmon"),
        },
        "predicate": {
            "command_line_contains": ["wmic", '/format:"http'],
            "event_id_equals": "1",
            "source_equals": "Microsoft-Windows-Sysmon",
        },
        "after_hits": 4,
        "misses": 6,
        "findings": 5,
        "changed_scenario": ("exec-wmi-xsl", "T1047"),
        "focused_tests": 6,
        "artifact_schema": "breachscope.p2_10b_measurement.v1",
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "sysmon_records_scanned": 732200,
            "raw_wmic_records": 29,
            "event1_wmic": 0,
            "event1_wmic_format": 0,
            "exact_predicate_matches": 0,
            "raw_prefilter_attack_candidate_matches": 1,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "Sysmon records",
            "benign_events_scanned": 732200,
            "benign_sysmon_records_scanned": 732200,
            "benign_raw_wmic_records": 29,
            "benign_exact_predicate_matches": 0,
        },
    },
    "p2-10c-domain-admins-4661": {
        "label": "P2-10C",
        "schema": "breachscope.p2_10c_remediation_measurement.v1",
        "rule_id": "R-DOMAIN-ADMINS-4661",
        "technique": "T1087.002",
        "severity": "low",
        "primary": ("ObjectName", "regex", "-512$"),
        "conditions": {
            "event_id": ("equals", "4661"),
            "source": ("equals", "Microsoft-Windows-Security-Auditing"),
            "ObjectType": ("equals", "SAM_GROUP"),
            "ObjectServer": ("equals", "Security Account Manager"),
        },
        "predicate": {
            "ObjectName_regex": "-512$",
            "event_id_equals": "4661",
            "source_equals": "Microsoft-Windows-Security-Auditing",
            "ObjectType_equals": "SAM_GROUP",
            "ObjectServer_equals": "Security Account Manager",
        },
        "after_hits": 5,
        "misses": 5,
        "findings": 7,
        "flagged_events": 7,
        "changed_scenario": ("discovery-domain-admins", "T1087.002"),
        "remaining_misses": [
            "ca-lsass-mimikatz",
            "lm-powershell-remoting",
            "lm-wmi",
            "lm-remote-service",
            "persist-hidden-run-key",
        ],
        "focused_tests": 6,
        "artifact_schema": "breachscope.p2_10c_measurement.v1",
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "non_sysmon_source_files_scanned": 351,
            "non_sysmon_events_scanned": 34423,
            "security_4661": 0,
            "sam_group_4661": 0,
            "sam_group_rid512": 0,
            "exact_predicate_matches": 0,
            "sysmon_events_from_p2_09d": 732200,
            "sysmon_provider_disjoint_from_rule_source_predicate": True,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "non-Sysmon events",
            "benign_events_scanned": 34423,
            "benign_non_sysmon_events_scanned": 34423,
            "benign_security_4661": 0,
            "benign_exact_predicate_matches": 0,
            "evaluator_control_scenario_hits": 4,
            "evaluator_control_findings": 5,
        },
    },
    "p2-10d-lsass-access-1010": {
        "label": "P2-10D",
        "schema": "breachscope.p2_10d_remediation_measurement.v1",
        "rule_id": "R-LSASS-ACCESS-1010",
        "technique": "T1003.001",
        "severity": "medium",
        "primary": ("TargetImage", "endswith", r"\lsass.exe"),
        "conditions": {
            "GrantedAccess": ("regex", "^0x0*1010$"),
            "event_id": ("equals", "10"),
            "source": ("equals", "Microsoft-Windows-Sysmon"),
        },
        "predicate": {
            "TargetImage_endswith": r"\lsass.exe",
            "GrantedAccess_regex": "^0x0*1010$",
            "event_id_equals": "10",
            "source_equals": "Microsoft-Windows-Sysmon",
        },
        "after_hits": 6,
        "misses": 4,
        "findings": 8,
        "flagged_events": 8,
        "changed_scenario": ("ca-lsass-mimikatz", "T1003.001"),
        "remaining_misses": [
            "lm-powershell-remoting",
            "lm-wmi",
            "lm-remote-service",
            "persist-hidden-run-key",
        ],
        "focused_tests": 6,
        "artifact_schema": "breachscope.p2_10d_measurement.v1",
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "sysmon_records_scanned": 732200,
            "sysmon_chunks_scanned": 11894,
            "lsass_event10_target_matches": 61,
            "exact_predicate_matches": 0,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "Sysmon records",
            "benign_events_scanned": 732200,
            "benign_sysmon_records_scanned": 732200,
            "benign_lsass_event10_target_matches": 61,
            "benign_exact_predicate_matches": 0,
        },
    },
    "p2-10e-winrm-wsmprovhost-child": {
        "label": "P2-10E",
        "schema": "breachscope.p2_10e_remediation_measurement.v1",
        "rule_id": "R-WINRM-WSMPROVHOST-CHILD",
        "technique": "T1021.006",
        "severity": "medium",
        "primary": ("ParentImage", "endswith", r"\wsmprovhost.exe"),
        "conditions": {
            "event_id": ("equals", "1"),
            "source": ("equals", "Microsoft-Windows-Sysmon"),
        },
        "predicate": {
            "ParentImage_endswith": r"\wsmprovhost.exe",
            "event_id_equals": "1",
            "source_equals": "Microsoft-Windows-Sysmon",
        },
        "after_hits": 7,
        "misses": 3,
        "findings": 9,
        "flagged_events": 9,
        "changed_scenario": ("lm-powershell-remoting", "T1021.006"),
        "remaining_misses": [
            "lm-wmi",
            "lm-remote-service",
            "persist-hidden-run-key",
        ],
        "focused_tests": 5,
        "artifact_schema": "breachscope.p2_10e_measurement.v1",
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "sysmon_records_scanned": 732200,
            "sysmon_event1_scanned": 2149,
            "exact_predicate_matches": 0,
            "parse_errors": 0,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "Sysmon records",
            "benign_events_scanned": 732200,
            "benign_sysmon_records_scanned": 732200,
            "benign_sysmon_event1_scanned": 2149,
            "benign_exact_predicate_matches": 0,
        },
    },

    "p2-10f-service-pathless-7045": {
        "label": "P2-10F",
        "schema": "breachscope.p2_10f_remediation_measurement.v1",
        "rule_id": "R-SERVICE-PATHLESS-7045",
        "technique": "T1569.002",
        "severity": "medium",
        "primary": (
            "ImagePath",
            "regex",
            r"^\s*(?:\x22[^\x22\\/:]+\.exe\x22|[^\\/: \t]+\.exe)(?:\s+.*)?$",
        ),
        "conditions": {
            "event_id": ("equals", "7045"),
            "source": ("equals", "Service Control Manager"),
        },
        "predicate": {
            "ImagePath_regex": r"^\s*(?:\x22[^\x22\\/:]+\.exe\x22|[^\\/: \t]+\.exe)(?:\s+.*)?$",
            "event_id_equals": "7045",
            "source_equals": "Service Control Manager",
        },
        "after_hits": 8,
        "misses": 2,
        "findings": 12,
        "flagged_events": 12,
        "changed_scenario": ("lm-remote-service", "T1569.002"),
        "remaining_misses": [
            "lm-wmi",
            "persist-hidden-run-key",
        ],
        "focused_tests": 8,
        "artifact_schema": "breachscope.external_holdout.result.v1",
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "evtx_files_scanned": 352,
            "service_control_manager_7045_scanned": 26,
            "pathless_imagepath_matches": 0,
            "exact_predicate_matches": 0,
            "parse_errors": 0,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "pinned public benign EVTX events",
            "benign_events_scanned": 766623,
            "benign_evtx_files_scanned": 352,
            "benign_service_control_manager_7045_scanned": 26,
            "benign_pathless_imagepath_matches": 0,
            "benign_exact_predicate_matches": 0,
            "benign_parse_errors": 0,
        },
    },

}


def _verify_live_rule(
    repo: Path,
    change: Mapping[str, Any],
    spec: Mapping[str, Any],
    label: str,
) -> None:
    _require(change.get("rule_id"), spec["rule_id"], f"{label} rule id")
    _require(change.get("mitre_technique"), spec["technique"], f"{label} technique")
    predicate = _mapping(change.get("predicate"), f"{label} predicate")
    for key, expected in _mapping(spec["predicate"], f"{label} predicate spec").items():
        _require(predicate.get(key), expected, f"{label} predicate {key}")

    rule = _load_rule(repo, str(change.get("rule_file") or ""), str(spec["rule_id"]))
    primary_field, primary_operator, primary_pattern = spec["primary"]
    _require(rule.get("field"), primary_field, f"live {label} rule field")
    _require(rule.get("operator"), primary_operator, f"live {label} rule operator")
    _require(str(rule.get("pattern")), str(primary_pattern), f"live {label} rule pattern")
    _require(rule.get("severity"), spec["severity"], f"live {label} severity")
    _require(rule.get("mitre_technique"), spec["technique"], f"live {label} technique")
    for field, expected in _mapping(spec["conditions"], f"{label} condition spec").items():
        operator, pattern = expected
        condition = _condition(rule, field)
        _require(condition.get("operator"), operator, f"live {label} {field} operator")
        _require(str(condition.get("pattern")), str(pattern), f"live {label} {field} value")


def _verify_record(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    remediation_id: str,
    previous_rule_hash: str,
    base: Mapping[str, Any],
    previous_attack_hits: int,
) -> tuple[str, int, dict[str, Any]]:
    if remediation_id not in SPECS:
        raise CurrentEvidenceError(f"unsupported remediation schema/id: {remediation_id}")
    spec = SPECS[remediation_id]
    label = str(spec["label"])
    _require(record.get("schema"), spec["schema"], f"{label} schema")
    _require(record.get("remediation_id"), remediation_id, f"{label} id")
    _require(record.get("from_rules_tree_sha256"), previous_rule_hash, f"{label} from rule hash")
    to_hash = str(record.get("to_rules_tree_sha256") or "")
    if len(to_hash) != 64:
        raise CurrentEvidenceError(f"{label} to_rules_tree_sha256 must be a full SHA-256")

    change = _mapping(record.get("rule_change"), f"{label} rule_change")
    _verify_live_rule(repo, change, spec, label)

    base_attack, base_corpus, base_benign, benign_source = _base_context(base)
    attack = _mapping(record.get("attack_external_baseline"), f"{label} attack baseline")
    _require(attack.get("baseline_id"), base_attack.get("baseline_id"), f"{label} attack baseline id")
    _require(
        attack.get("corpus_manifest_sha256"),
        base_corpus.get("manifest_sha256"),
        f"{label} attack manifest hash",
    )
    _require(attack.get("labels_sha256"), base_corpus.get("labels_sha256"), f"{label} attack labels hash")
    _require(int(attack.get("source_files", -1)), 10, f"{label} attack source files")
    _require(int(attack.get("events", -1)), 202, f"{label} attack events")
    _require(
        int(attack.get("before_scenario_hits", -1)),
        previous_attack_hits,
        f"{label} before attack hits",
    )
    after_hits = int(attack.get("after_scenario_hits", -1))
    _require(after_hits, int(spec["after_hits"]), f"{label} after attack hits")
    _require(int(attack.get("scenario_misses", -1)), int(spec["misses"]), f"{label} attack misses")
    _require(int(attack.get("scenario_total", -1)), 10, f"{label} attack total")
    _require(
        float(attack.get("after_scenario_hit_rate", -1.0)),
        after_hits / 10.0,
        f"{label} hit rate",
    )
    _require(int(attack.get("findings", -1)), int(spec["findings"]), f"{label} findings")
    if "flagged_events" in spec:
        _require(
            int(attack.get("flagged_events", -1)),
            int(spec["flagged_events"]),
            f"{label} flagged events",
        )
    scenario_id, technique = spec["changed_scenario"]
    changed = _mapping(attack.get("changed_scenario"), f"{label} changed scenario")
    _require(changed.get("scenario_id"), scenario_id, f"{label} changed scenario id")
    _require(changed.get("expected_technique"), technique, f"{label} changed technique")
    _require(changed.get("before_status"), "miss", f"{label} before status")
    _require(changed.get("after_status"), "hit", f"{label} after status")
    if "remaining_misses" in spec:
        _require(
            attack.get("remaining_miss_scenarios"),
            spec["remaining_misses"],
            f"{label} remaining misses",
        )

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign proof")
    _require(benign.get("baseline_id"), base_benign.get("baseline_id"), f"{label} benign baseline id")
    _require(benign.get("corpus_sha256"), benign_source.get("sha256"), f"{label} benign corpus hash")
    for key, expected in _mapping(spec["benign_expected"], f"{label} benign spec").items():
        actual = benign.get(key)
        if isinstance(expected, bool):
            _require(actual, expected, f"{label} benign {key}")
        else:
            _require(int(actual if actual is not None else -1), int(expected), f"{label} benign {key}")
    if remediation_id in {"p2-10b-wmi-xsl", "p2-10c-domain-admins-4661", "p2-10d-lsass-access-1010"}:
        if int(benign.get("probe_run_id", 0)) <= 0:
            raise CurrentEvidenceError(f"{label} benign probe run id is required")
    if remediation_id in {"p2-10b-wmi-xsl", "p2-10d-lsass-access-1010"}:
        probe_commit = str(benign.get("probe_commit") or "")
        if len(probe_commit) != 40:
            raise CurrentEvidenceError(f"{label} benign probe commit must be a full Git SHA")

    if remediation_id == "p2-10c-domain-admins-4661":
        control = _mapping(record.get("evaluator_reconstruction_fix"), f"{label} evaluator control")
        if int(control.get("control_github_actions_run_id", 0)) <= 0:
            raise CurrentEvidenceError(f"{label} evaluator control run id is required")
        _require(control.get("control_rules_tree_sha256"), previous_rule_hash, f"{label} evaluator control rule hash")
        _require(int(control.get("control_rules", -1)), 54, f"{label} evaluator control rules")
        _require(int(control.get("control_scenario_hits", -1)), previous_attack_hits, f"{label} evaluator control hits")
        _require(int(control.get("control_scenario_misses", -1)), 6, f"{label} evaluator control misses")
        _require(int(control.get("control_findings", -1)), 5, f"{label} evaluator control findings")
        _require(control.get("result_unchanged"), True, f"{label} evaluator control unchanged")
        _require(int(control.get("reconstruction_tests_passed", -1)), 2, f"{label} reconstruction test count")

    _verify_execution(
        record,
        label,
        int(spec["focused_tests"]),
        spec.get("artifact_schema"),
    )
    _verify_claims(record, label)

    summary = {
        "remediation_id": remediation_id,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_rule_hash,
        "to_rules_tree_sha256": to_hash,
        "attack_scenario_hits_before": previous_attack_hits,
        "attack_scenario_hits_after": after_hits,
        "attack_scenario_total": 10,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
        "record_path": record_path.relative_to(repo).as_posix(),
    }
    summary.update(dict(spec["summary"]))
    return to_hash, after_hits, summary


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = _load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    base_path = _relative_file(repo, chain.get("base_benchmark"), "base benchmark")
    base = _verify_base_benchmark(repo, base_path)
    _require(
        chain.get("base_rules_tree_sha256"),
        base["rules_tree_sha256"],
        "current evidence base rule hash",
    )

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
        record_path = _relative_file(
            repo,
            item.get("measurement_record"),
            f"{remediation_id} measurement record",
        )
        record = _load_yaml(record_path)
        previous_rule_hash, previous_attack_hits, verified = _verify_record(
            repo,
            record_path,
            record,
            remediation_id,
            previous_rule_hash,
            base,
            previous_attack_hits,
        )
        verified_remediations.append(verified)

    _require(ordered_ids, list(SPECS), "remediation chain order/content")
    current_rule_hash, rule_file_count = historical._rules_tree_hash(repo / "rules")
    _require(
        previous_rule_hash,
        current_rule_hash,
        "current rule tree explained by remediation chain",
    )

    claims = _mapping(chain.get("claim_boundary"), "current evidence claim boundary")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", "current production accuracy boundary")
    _require(
        claims.get("production_false_positive_rate"),
        "NOT_CLAIMED",
        "current production FPR boundary",
    )
    _require(claims.get("final_blind_holdout"), False, "current final blind holdout boundary")
    _require(
        claims.get("fresh_full_benign_fpr_for_current_rulepack"),
        "NOT_CLAIMED",
        "current fresh benign FPR boundary",
    )

    return {
        "schema": "breachscope.current_detection_evidence_verification.v1",
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
        chain_path = _relative_file(repo, args.chain, "current evidence chain")
        result = verify(repo, chain_path)
    except (CurrentEvidenceError, historical.BenchmarkError, OSError, yaml.YAMLError) as exc:
        print(f"Current detection evidence verification: FAIL: {exc}")
        return 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print("Current detection evidence verification: PASS")
        print(f"Base rules SHA-256: {result['base_rules_tree_sha256']}")
        print(f"Current rules SHA-256: {result['current_rules_tree_sha256']}")
        print(
            "Attack external baseline: "
            f"{result['base_attack_scenario_hits']}/{result['attack_scenario_total']} -> "
            f"{result['current_attack_scenario_hits']}/{result['attack_scenario_total']} scenario hits"
        )
        for remediation in result["remediations"]:
            print(
                f"{remediation['remediation_id']}: benign incremental predicate matches="
                f"{remediation['benign_exact_predicate_matches']} / "
                f"{remediation['benign_events_scanned']} {remediation['benign_scope']}"
            )
        print("Fresh full benign FPR for current rulepack: NOT CLAIMED")
        print("Production accuracy/FPR: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
