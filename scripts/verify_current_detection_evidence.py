#!/usr/bin/env python3
"""Verify the historical P2-09E benchmark plus recorded rule-remediation chain."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

import verify_reproducible_benchmark as historical


CHAIN_SCHEMA = "breachscope.current_detection_evidence_chain.v1"
P2_10A_SCHEMA = "breachscope.p2_10a_remediation_measurement.v1"
P2_10B_SCHEMA = "breachscope.p2_10b_remediation_measurement.v1"
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
        attack, attack_files = historical._verify_attack(
            repo, attack_component, base_rule_hash
        )
        benign, benign_files = historical._verify_benign(
            repo, benign_component, base_rule_hash
        )
        claims = historical._mapping(
            manifest.get("claim_boundary"), "benchmark claim_boundary"
        )
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


def _base_attack_context(base: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    base_attack = _mapping(base.get("attack"), "base attack")
    base_attack_result = _mapping(base.get("attack_result"), "base attack result")
    base_corpus = _mapping(base_attack_result.get("corpus"), "base attack corpus")
    return base_attack, base_corpus


def _base_benign_context(base: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    base_benign = _mapping(base.get("benign"), "base benign")
    benign_source_doc = _mapping(base.get("benign_source"), "base benign source document")
    benign_source = _mapping(benign_source_doc.get("source"), "base benign source")
    return base_benign, benign_source


def _verify_execution(
    record: Mapping[str, Any], label: str, focused_tests: int
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
    return execution


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


def _verify_p2_10a(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    previous_rule_hash: str,
    base: Mapping[str, Any],
    previous_attack_hits: int,
) -> tuple[str, int, dict[str, Any]]:
    label = "P2-10A"
    _require(record.get("schema"), P2_10A_SCHEMA, f"{label} schema")
    _require(record.get("remediation_id"), "p2-10a-scheduled-task-4698", f"{label} id")
    _require(record.get("from_rules_tree_sha256"), previous_rule_hash, f"{label} from rule hash")
    to_hash = str(record.get("to_rules_tree_sha256") or "")
    if len(to_hash) != 64:
        raise CurrentEvidenceError(f"{label} to_rules_tree_sha256 must be a full SHA-256")

    change = _mapping(record.get("rule_change"), f"{label} rule_change")
    predicate = _mapping(change.get("predicate"), f"{label} predicate")
    _require(change.get("rule_id"), "R-SCHTASK-4698", f"{label} rule id")
    _require(change.get("mitre_technique"), "T1053.005", f"{label} technique")
    _require(predicate.get("event_id_equals"), "4698", f"{label} event id")
    _require(
        predicate.get("source_equals"),
        "Microsoft-Windows-Security-Auditing",
        f"{label} provider",
    )

    rule = _load_rule(repo, str(change.get("rule_file") or ""), str(change["rule_id"]))
    _require(rule.get("field"), "event_id", f"live {label} rule field")
    _require(rule.get("operator"), "equals", f"live {label} rule operator")
    _require(str(rule.get("pattern")), "4698", f"live {label} rule event id")
    _require(rule.get("severity"), "low", f"live {label} severity")
    _require(rule.get("mitre_technique"), "T1053.005", f"live {label} technique")
    provider = _condition(rule, "source")
    _require(provider.get("operator"), "equals", f"live {label} provider operator")
    _require(
        provider.get("pattern"),
        "Microsoft-Windows-Security-Auditing",
        f"live {label} provider value",
    )

    attack = _mapping(record.get("attack_external_baseline"), f"{label} attack baseline")
    base_attack, base_corpus = _base_attack_context(base)
    _require(attack.get("baseline_id"), base_attack.get("baseline_id"), f"{label} attack baseline id")
    _require(attack.get("corpus_manifest_sha256"), base_corpus.get("manifest_sha256"), f"{label} attack manifest hash")
    _require(attack.get("labels_sha256"), base_corpus.get("labels_sha256"), f"{label} attack labels hash")
    _require(int(attack.get("source_files", -1)), 10, f"{label} attack source files")
    _require(int(attack.get("events", -1)), 202, f"{label} attack events")
    _require(int(attack.get("before_scenario_hits", -1)), previous_attack_hits, f"{label} before attack hits")
    after_hits = int(attack.get("after_scenario_hits", -1))
    _require(after_hits, 3, f"{label} after attack hits")
    _require(int(attack.get("scenario_misses", -1)), 7, f"{label} attack misses")
    _require(int(attack.get("scenario_total", -1)), 10, f"{label} attack total")
    _require(float(attack.get("after_scenario_hit_rate", -1.0)), 0.3, f"{label} hit rate")
    _require(int(attack.get("findings", -1)), 4, f"{label} findings")
    changed = _mapping(attack.get("changed_scenario"), f"{label} changed scenario")
    _require(changed.get("scenario_id"), "exec-scheduled-task", f"{label} changed scenario id")
    _require(changed.get("expected_technique"), "T1053.005", f"{label} changed technique")
    _require(changed.get("before_status"), "miss", f"{label} before status")
    _require(changed.get("after_status"), "hit", f"{label} after status")

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign proof")
    base_benign, benign_source = _base_benign_context(base)
    _require(benign.get("baseline_id"), base_benign.get("baseline_id"), f"{label} benign baseline id")
    _require(benign.get("corpus_sha256"), benign_source.get("sha256"), f"{label} benign corpus hash")
    _require(int(benign.get("corpus_total_events_from_p2_09d", -1)), int(base_benign["events"]), f"{label} benign total events")
    _require(int(benign.get("non_sysmon_source_files_scanned", -1)), 351, f"{label} non-Sysmon files")
    _require(int(benign.get("non_sysmon_events_scanned", -1)), 34423, f"{label} non-Sysmon events")
    _require(int(benign.get("exact_predicate_matches", -1)), 0, f"{label} benign predicate matches")
    _require(int(benign.get("sysmon_events_from_p2_09d", -1)), 732200, f"{label} Sysmon events")
    _require(34423 + 732200, int(base_benign["events"]), f"{label} benign corpus partition accounting")
    _require(benign.get("sysmon_provider_disjoint_from_rule_source_predicate"), True, f"{label} provider-disjoint proof")
    _require(benign.get("fresh_full_fp_tn_rerun"), False, f"{label} full benign rerun boundary")

    _verify_execution(record, label, 4)
    _verify_claims(record, label)
    return to_hash, after_hits, {
        "remediation_id": record["remediation_id"],
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_rule_hash,
        "to_rules_tree_sha256": to_hash,
        "attack_scenario_hits_before": previous_attack_hits,
        "attack_scenario_hits_after": after_hits,
        "attack_scenario_total": 10,
        "benign_scope": "non-Sysmon events",
        "benign_events_scanned": 34423,
        "benign_non_sysmon_events_scanned": 34423,
        "benign_exact_predicate_matches": 0,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
        "record_path": record_path.relative_to(repo).as_posix(),
    }


def _verify_p2_10b(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    previous_rule_hash: str,
    base: Mapping[str, Any],
    previous_attack_hits: int,
) -> tuple[str, int, dict[str, Any]]:
    label = "P2-10B"
    _require(record.get("schema"), P2_10B_SCHEMA, f"{label} schema")
    _require(record.get("remediation_id"), "p2-10b-wmi-xsl", f"{label} id")
    _require(record.get("from_rules_tree_sha256"), previous_rule_hash, f"{label} from rule hash")
    to_hash = str(record.get("to_rules_tree_sha256") or "")
    if len(to_hash) != 64:
        raise CurrentEvidenceError(f"{label} to_rules_tree_sha256 must be a full SHA-256")

    change = _mapping(record.get("rule_change"), f"{label} rule_change")
    predicate = _mapping(change.get("predicate"), f"{label} predicate")
    _require(change.get("rule_id"), "R-WMI-XSL-Remote", f"{label} rule id")
    _require(change.get("mitre_technique"), "T1047", f"{label} technique")
    _require(predicate.get("command_line_contains"), ["wmic", '/format:"http'], f"{label} command predicates")
    _require(predicate.get("event_id_equals"), "1", f"{label} event id")
    _require(predicate.get("source_equals"), "Microsoft-Windows-Sysmon", f"{label} provider")

    rule = _load_rule(repo, str(change.get("rule_file") or ""), str(change["rule_id"]))
    _require(rule.get("field"), "command_line", f"live {label} rule field")
    _require(rule.get("operator"), "contains", f"live {label} rule operator")
    _require(rule.get("pattern"), "wmic", f"live {label} primary command predicate")
    _require(rule.get("severity"), "low", f"live {label} severity")
    _require(rule.get("mitre_technique"), "T1047", f"live {label} technique")
    command = _condition(rule, "command_line")
    event_id = _condition(rule, "event_id")
    source = _condition(rule, "source")
    _require(command.get("operator"), "contains", f"live {label} format operator")
    _require(command.get("pattern"), '/format:"http', f"live {label} format predicate")
    _require(event_id.get("operator"), "equals", f"live {label} event id operator")
    _require(str(event_id.get("pattern")), "1", f"live {label} event id value")
    _require(source.get("operator"), "equals", f"live {label} provider operator")
    _require(source.get("pattern"), "Microsoft-Windows-Sysmon", f"live {label} provider value")

    attack = _mapping(record.get("attack_external_baseline"), f"{label} attack baseline")
    base_attack, base_corpus = _base_attack_context(base)
    _require(attack.get("baseline_id"), base_attack.get("baseline_id"), f"{label} attack baseline id")
    _require(attack.get("corpus_manifest_sha256"), base_corpus.get("manifest_sha256"), f"{label} attack manifest hash")
    _require(attack.get("labels_sha256"), base_corpus.get("labels_sha256"), f"{label} attack labels hash")
    _require(int(attack.get("source_files", -1)), 10, f"{label} attack source files")
    _require(int(attack.get("events", -1)), 202, f"{label} attack events")
    _require(int(attack.get("before_scenario_hits", -1)), previous_attack_hits, f"{label} before attack hits")
    after_hits = int(attack.get("after_scenario_hits", -1))
    _require(after_hits, 4, f"{label} after attack hits")
    _require(int(attack.get("scenario_misses", -1)), 6, f"{label} attack misses")
    _require(int(attack.get("scenario_total", -1)), 10, f"{label} attack total")
    _require(float(attack.get("after_scenario_hit_rate", -1.0)), 0.4, f"{label} hit rate")
    _require(int(attack.get("findings", -1)), 5, f"{label} findings")
    changed = _mapping(attack.get("changed_scenario"), f"{label} changed scenario")
    _require(changed.get("scenario_id"), "exec-wmi-xsl", f"{label} changed scenario id")
    _require(changed.get("expected_technique"), "T1047", f"{label} changed technique")
    _require(changed.get("before_status"), "miss", f"{label} before status")
    _require(changed.get("after_status"), "hit", f"{label} after status")
    unchanged = _mapping(attack.get("intentionally_unchanged_scenario"), f"{label} unchanged scenario")
    _require(unchanged.get("scenario_id"), "lm-wmi", f"{label} unchanged scenario id")
    _require(unchanged.get("expected_technique"), "T1047", f"{label} unchanged technique")
    _require(unchanged.get("after_status"), "miss", f"{label} unchanged status")

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign proof")
    base_benign, benign_source = _base_benign_context(base)
    _require(benign.get("baseline_id"), base_benign.get("baseline_id"), f"{label} benign baseline id")
    _require(benign.get("corpus_sha256"), benign_source.get("sha256"), f"{label} benign corpus hash")
    _require(int(benign.get("corpus_total_events_from_p2_09d", -1)), int(base_benign["events"]), f"{label} benign total events")
    _require(int(benign.get("sysmon_records_scanned", -1)), 732200, f"{label} Sysmon records")
    _require(int(benign.get("raw_wmic_records", -1)), 29, f"{label} raw WMIC records")
    _require(int(benign.get("event1_wmic", -1)), 0, f"{label} Event ID 1 WMIC records")
    _require(int(benign.get("event1_wmic_format", -1)), 0, f"{label} WMIC format records")
    _require(int(benign.get("exact_predicate_matches", -1)), 0, f"{label} benign predicate matches")
    _require(int(benign.get("raw_prefilter_attack_candidate_matches", -1)), 1, f"{label} attack prefilter proof")
    if int(benign.get("probe_run_id", 0)) <= 0:
        raise CurrentEvidenceError(f"{label} benign probe run id is required")
    probe_commit = str(benign.get("probe_commit") or "")
    if len(probe_commit) != 40:
        raise CurrentEvidenceError(f"{label} benign probe commit must be a full Git SHA")
    _require(benign.get("fresh_full_fp_tn_rerun"), False, f"{label} full benign rerun boundary")

    execution = _verify_execution(record, label, 6)
    _require(execution.get("artifact_record_schema"), "breachscope.p2_10b_measurement.v1", f"{label} artifact record schema")
    _verify_claims(record, label)
    return to_hash, after_hits, {
        "remediation_id": record["remediation_id"],
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_rule_hash,
        "to_rules_tree_sha256": to_hash,
        "attack_scenario_hits_before": previous_attack_hits,
        "attack_scenario_hits_after": after_hits,
        "attack_scenario_total": 10,
        "benign_scope": "Sysmon records",
        "benign_events_scanned": 732200,
        "benign_sysmon_records_scanned": 732200,
        "benign_raw_wmic_records": 29,
        "benign_exact_predicate_matches": 0,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
        "record_path": record_path.relative_to(repo).as_posix(),
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = _load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    base_path = _relative_file(repo, chain.get("base_benchmark"), "base benchmark")
    base = _verify_base_benchmark(repo, base_path)
    _require(chain.get("base_rules_tree_sha256"), base["rules_tree_sha256"], "current evidence base rule hash")

    previous_rule_hash = str(base["rules_tree_sha256"])
    previous_attack_hits = int(base["attack"]["scenario_hits"])
    verified_remediations: list[dict[str, Any]] = []
    remediations = chain.get("remediations")
    if not isinstance(remediations, list):
        raise CurrentEvidenceError("remediations must be a list")

    seen_ids: set[str] = set()
    for item in remediations:
        if not isinstance(item, Mapping):
            raise CurrentEvidenceError("each remediation chain item must be a mapping")
        remediation_id = str(item.get("remediation_id") or "")
        if not remediation_id or remediation_id in seen_ids:
            raise CurrentEvidenceError("remediation_id values must be non-empty and unique")
        seen_ids.add(remediation_id)
        record_path = _relative_file(
            repo, item.get("measurement_record"), f"{remediation_id} measurement record"
        )
        record = _load_yaml(record_path)
        _require(record.get("remediation_id"), remediation_id, f"{remediation_id} record id")
        if remediation_id == "p2-10a-scheduled-task-4698":
            previous_rule_hash, previous_attack_hits, verified = _verify_p2_10a(
                repo, record_path, record, previous_rule_hash, base, previous_attack_hits
            )
        elif remediation_id == "p2-10b-wmi-xsl":
            previous_rule_hash, previous_attack_hits, verified = _verify_p2_10b(
                repo, record_path, record, previous_rule_hash, base, previous_attack_hits
            )
        else:
            raise CurrentEvidenceError(f"unsupported remediation schema/id: {remediation_id}")
        verified_remediations.append(verified)

    current_rule_hash, rule_file_count = historical._rules_tree_hash(repo / "rules")
    _require(previous_rule_hash, current_rule_hash, "current rule tree explained by remediation chain")

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
