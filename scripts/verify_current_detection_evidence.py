#!/usr/bin/env python3
"""Verify P2-09E/P2-10 remediation evidence plus later calibration transitions."""
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
CALIBRATION_ID = "p2-11d-local-account-4720"
CALIBRATION_SCHEMA = "breachscope.p2_11d_external_calibration_measurement.v1"
EXPECTED_CALIBRATION_OUTCOMES = {
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

    rule_path = repo / rule_file
    _require(
        legacy._git_blob_sha1(rule_path),
        str(change.get("rule_file_git_blob_sha1") or ""),
        "live P2-11D rule file blob",
    )


def _verify_p2_11d_calibration(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    previous_rule_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "P2-11D"
    _require(record.get("schema"), CALIBRATION_SCHEMA, f"{label} schema")
    _require(record.get("calibration_id"), CALIBRATION_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("from_rules_tree_sha256"), previous_rule_hash, f"{label} from rule hash")
    to_hash = str(record.get("to_rules_tree_sha256") or "")
    if len(to_hash) != 64:
        raise CurrentEvidenceError(f"{label} to_rules_tree_sha256 must be a full SHA-256")

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
    if int(benign.get("probe_run_id", 0)) <= 0 or int(benign.get("artifact_id", 0)) <= 0:
        raise CurrentEvidenceError(f"{label} benign probe run/artifact id required")
    if len(str(benign.get("artifact_digest_sha256") or "")) != 64:
        raise CurrentEvidenceError(f"{label} benign artifact digest must be SHA-256")

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
    if int(execution.get("github_actions_run_id", 0)) <= 0:
        raise CurrentEvidenceError(f"{label} GitHub Actions run id required")
    if int(execution.get("artifact_id", 0)) <= 0:
        raise CurrentEvidenceError(f"{label} artifact id required")
    if len(str(execution.get("artifact_digest_sha256") or "")) != 64:
        raise CurrentEvidenceError(f"{label} artifact digest must be SHA-256")

    aggregate_path = legacy._relative_file(
        repo,
        execution.get("aggregate_result"),
        f"{label} aggregate result",
    )
    aggregate_sha = _sha256(aggregate_path)
    _require(
        aggregate_sha,
        execution.get("aggregate_result_sha256"),
        f"{label} aggregate SHA-256",
    )
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    if not isinstance(aggregate, dict):
        raise CurrentEvidenceError(f"{label} aggregate result must be a mapping")
    _require(
        aggregate.get("schema"),
        "breachscope.p2_11d_external_calibration_result.v1",
        f"{label} aggregate schema",
    )
    _require(aggregate.get("evaluation_class"), "external_calibration", f"{label} aggregate class")
    _require(aggregate.get("detector_repo_commit"), record.get("measurement_repo_commit"), f"{label} detector commit")
    _require(aggregate.get("rules_tree_sha256"), to_hash, f"{label} aggregate rule hash")
    _require(int(aggregate.get("rules", -1)), 61, f"{label} aggregate rules")
    _require(int(aggregate.get("events", -1)), 902, f"{label} aggregate events")
    _require(int(aggregate.get("scenario_hits", -1)), 2, f"{label} aggregate hits")
    _require(int(aggregate.get("scenario_misses", -1)), 10, f"{label} aggregate misses")
    _require(int(aggregate.get("findings", -1)), 84, f"{label} aggregate findings")
    _require(int(aggregate.get("flagged_events", -1)), 80, f"{label} aggregate flagged events")
    outcomes = aggregate.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != 12:
        raise CurrentEvidenceError(f"{label} aggregate must contain 12 outcomes")
    observed = {str(row.get("scenario_id")): str(row.get("status")) for row in outcomes if isinstance(row, Mapping)}
    _require(observed, EXPECTED_CALIBRATION_OUTCOMES, f"{label} outcome map")
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
        "calibration_id": CALIBRATION_ID,
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
        "benign_security_4720_events": 3,
        "benign_exact_predicate_matches": 0,
        "record_path": record_path.relative_to(repo).as_posix(),
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = legacy._load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    base_path = legacy._relative_file(repo, chain.get("base_benchmark"), "base benchmark")
    base = legacy._verify_base_benchmark(repo, base_path)
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
        record_path = legacy._relative_file(
            repo,
            item.get("measurement_record"),
            f"{remediation_id} measurement record",
        )
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
    calibration_ids = [str(row.get("calibration_id") or "") for row in calibrations if isinstance(row, Mapping)]
    _require(calibration_ids, [CALIBRATION_ID], "calibration chain order/content")
    verified_calibrations: list[dict[str, Any]] = []
    for item in calibrations:
        record_path = legacy._relative_file(
            repo,
            item.get("measurement_record"),
            f"{CALIBRATION_ID} measurement record",
        )
        record = legacy._load_yaml(record_path)
        previous_rule_hash, verified = _verify_p2_11d_calibration(
            repo,
            record_path,
            record,
            previous_rule_hash,
        )
        verified_calibrations.append(verified)

    current_rule_hash, rule_file_count = legacy.historical._rules_tree_hash(repo / "rules")
    _require(
        previous_rule_hash,
        current_rule_hash,
        "current rule tree explained by remediation/calibration chain",
    )

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
        "schema": "breachscope.current_detection_evidence_verification.v2",
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
    except (CurrentEvidenceError, legacy.historical.BenchmarkError, OSError, yaml.YAMLError, json.JSONDecodeError) as exc:
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
