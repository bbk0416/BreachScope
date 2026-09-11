#!/usr/bin/env python3
"""Verify the current detection-evidence chain through P2-11F."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

import verify_current_detection_evidence_p2_11e as previous


legacy = previous.legacy
CHAIN_SCHEMA = previous.CHAIN_SCHEMA
DEFAULT_CHAIN = previous.DEFAULT_CHAIN
CurrentEvidenceError = previous.CurrentEvidenceError

P2_11D_ID = previous.P2_11D_ID
P2_11E_ID = previous.P2_11E_ID
P2_11F_ID = "p2-11f-t1006-direct-volume-access"
P2_11F_SCHEMA = "breachscope.p2_11f_external_calibration_measurement.v1"
P2_11F_OUTCOMES = {
    "T1003-1": "miss",
    "T1003-2": "miss",
    "T1006-1": "hit",
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
P2_11E_RULE_BLOB = "7af75f7edefa93c38ebb2e2a41ca9cc885e606c3"
P2_11F_RULE_BLOB = "4dc26895301a6ff1212a83e86f3d1f02248615e3"
P2_11F_AGGREGATE_SHA256 = "8ffae533b35cabdf405b81d775da882d71ff28bf0ce6d75147a776b3633b91ca"
P2_11F_BENIGN_SHA256 = "fa1e171892ae95306c30097879e81e1bb4f2d2f9a1649ed869971bcdbbd540f6"


def _require(actual: Any, expected: Any, label: str) -> None:
    previous._require(actual, expected, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    return previous._mapping(value, label)


def _verify_p2_11e_with_historical_rule_blob(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    previous_rule_hash: str,
) -> tuple[str, dict[str, Any]]:
    """Reuse the exact P2-11E verifier while keeping its rule-file blob historical.

    P2-11F appends a rule to the same YAML file, so the P2-11E measurement must
    keep its recorded historical blob rather than require that old whole-file
    blob to equal the current live file. Individual P2-11E rules are still
    checked against the current live rule set by the preserved verifier.
    """
    change = _mapping(record.get("rule_change"), "P2-11E rule change")
    _require(change.get("rule_file_git_blob_sha1"), P2_11E_RULE_BLOB, "P2-11E historical rule file blob")

    original_blob = legacy._git_blob_sha1

    def historical_blob(path: Path) -> str:
        if Path(path).as_posix().endswith("rules/p2_11_calibration_rules.yml"):
            return P2_11E_RULE_BLOB
        return original_blob(path)

    legacy._git_blob_sha1 = historical_blob
    try:
        return previous._verify_p2_11e_calibration(
            repo,
            record_path,
            record,
            previous_rule_hash,
        )
    finally:
        legacy._git_blob_sha1 = original_blob


def _verify_live_p2_11f_rule(repo: Path, record: Mapping[str, Any]) -> None:
    label = "P2-11F"
    change = _mapping(record.get("rule_change"), f"{label} rule change")
    rule_file = str(change.get("rule_file") or "")
    _require(rule_file, "rules/p2_11_calibration_rules.yml", f"{label} rule file")
    _require(change.get("rule_file_git_blob_sha1"), P2_11F_RULE_BLOB, f"{label} recorded rule file blob")
    _require(legacy._git_blob_sha1(repo / rule_file), P2_11F_RULE_BLOB, f"live {label} rule file blob")

    rows = change.get("rules")
    if not isinstance(rows, list) or len(rows) != 1:
        raise CurrentEvidenceError(f"{label} must record exactly one rule")
    row = _mapping(rows[0], f"{label} recorded rule")
    _require(row.get("rule_id"), "R-DIRECT-VOLUME-RAW-LOGICAL-DRIVE", f"{label} rule id")
    _require(row.get("mitre_technique"), "T1006", f"{label} technique")
    predicate = _mapping(row.get("predicate"), f"{label} predicate")
    _require(predicate.get("source_equals"), "Microsoft-Windows-Sysmon", f"{label} predicate source")
    _require(str(predicate.get("event_id_equals")), "1", f"{label} predicate event id")
    _require(predicate.get("command_line_regex"), r"\\{2}\.\\[A-Za-z]:", f"{label} predicate command line")

    rule = legacy._load_rule(repo, rule_file, "R-DIRECT-VOLUME-RAW-LOGICAL-DRIVE")
    for key, expected in {
        "field": "command_line",
        "operator": "regex",
        "pattern": r"\\{2}\.\\[A-Za-z]:",
        "severity": "medium",
        "mitre_technique": "T1006",
    }.items():
        _require(str(rule.get(key)), expected, f"live {label} {key}")
    for field, operator, pattern in (
        ("source", "equals", "Microsoft-Windows-Sysmon"),
        ("event_id", "equals", "1"),
    ):
        condition = legacy._condition(rule, field)
        _require(condition.get("operator"), operator, f"live {label} {field} operator")
        _require(str(condition.get("pattern")), pattern, f"live {label} {field} pattern")


def _verify_p2_11f_benign(repo: Path, record: Mapping[str, Any]) -> None:
    label = "P2-11F"
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
        "sysmon_event9": 4292,
        "powershell_event1": 5,
        "parse_errors": 0,
        "raw_volume_path_any": 0,
        "powershell_raw_volume": 0,
        "filestream_raw_volume": 0,
        "filestream_open_read_raw_volume": 0,
    }.items():
        _require(int(benign.get(key, -1)), expected, f"{label} benign {key}")
    for key, expected in {
        "probe_run_id": 34441210104,
        "artifact_id": 10138066242,
    }.items():
        _require(int(benign.get(key, 0)), expected, f"{label} benign {key}")
    _require(benign.get("probe_commit"), "3dd821f47eff85bdff0f4452802f00d948cda444", f"{label} benign probe commit")
    _require(
        benign.get("artifact_digest_sha256"),
        "0c0abfc1c9772e83909c3aed31368e02a25fab2868c6ebbd17288b68cc36900a",
        f"{label} benign artifact digest",
    )
    _require(benign.get("artifact_inner_result_sha256"), P2_11F_BENIGN_SHA256, f"{label} benign inner SHA")
    _require(benign.get("stored_result_sha256"), P2_11F_BENIGN_SHA256, f"{label} benign stored recorded SHA")
    _require(benign.get("fresh_full_fp_tn_rerun"), False, f"{label} benign fresh full rerun")

    stored_path = legacy._relative_file(repo, benign.get("stored_result"), f"{label} benign stored result")
    _require(previous._sha256(stored_path), P2_11F_BENIGN_SHA256, f"{label} benign stored SHA")
    stored = json.loads(stored_path.read_text(encoding="utf-8"))
    _require(stored.get("schema"), "breachscope.p2_11f_t1006_benign_probe.v1", f"{label} benign stored schema")
    _require(stored.get("corpus_sha256"), benign.get("corpus_sha256"), f"{label} benign stored corpus")
    scope = _mapping(stored.get("scope"), f"{label} benign stored scope")
    for key, expected in {
        "sysmon_records": 732200,
        "sysmon_chunks": 11894,
        "sysmon_event1": 2149,
        "sysmon_event9": 4292,
        "powershell_event1": 5,
        "parse_errors": 0,
    }.items():
        _require(int(scope.get(key, -1)), expected, f"{label} benign stored {key}")
    candidates = _mapping(stored.get("candidate_counts"), f"{label} benign candidates")
    for key in (
        "raw_volume_path_any",
        "powershell_raw_volume",
        "filestream_raw_volume",
        "filestream_open_read_raw_volume",
    ):
        _require(int(candidates.get(key, -1)), 0, f"{label} benign stored {key}")
    claims = _mapping(stored.get("claim_boundary"), f"{label} benign stored claims")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} benign production FPR")
    _require(claims.get("fresh_full_rulepack_fpr"), "NOT_CLAIMED", f"{label} benign full-rulepack FPR")


def _verify_p2_11f_calibration(
    repo: Path,
    record_path: Path,
    record: Mapping[str, Any],
    previous_rule_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "P2-11F"
    _require(record.get("schema"), P2_11F_SCHEMA, f"{label} schema")
    _require(record.get("calibration_id"), P2_11F_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("from_rules_tree_sha256"), previous_rule_hash, f"{label} from rule hash")
    to_hash = previous._require_sha256(record.get("to_rules_tree_sha256"), f"{label} to rule hash")
    _require(
        record.get("measurement_repo_commit"),
        "e2f78b3addb0a6f7549f8911537c9999b65e3609",
        f"{label} detector commit",
    )
    _verify_live_p2_11f_rule(repo, record)
    _verify_p2_11f_benign(repo, record)

    calibration = _mapping(record.get("external_calibration"), f"{label} calibration")
    for key, expected in {
        "previous_measurement_record": "external_baseline/results/p2_11e_aa08c6be/measurement.yaml",
        "source_repository": "arniki/atomic-evtx",
        "source_commit": "8de5fa8f158b4d72d1e3c6f07053162c90ee6238",
        "selection_frozen_commit": "7541214400507afddca40a22f2adb22504fc3946",
    }.items():
        _require(calibration.get(key), expected, f"{label} calibration {key}")
    for key, expected in {
        "before_scenario_hits": 4,
        "after_scenario_hits": 5,
        "scenario_misses": 7,
        "scenario_total": 12,
        "events": 902,
        "rules": 64,
        "findings": 89,
        "flagged_events": 85,
    }.items():
        _require(int(calibration.get(key, -1)), expected, f"{label} calibration {key}")
    _require(calibration.get("changed_scenarios"), ["T1006-1"], f"{label} changed scenarios")
    _require(
        calibration.get("remaining_miss_scenarios"),
        ["T1003-1", "T1003-2", "T1027-2", "T1021.001-1", "T1021.001-2", "T1047-1", "T1047-2"],
        f"{label} remaining misses",
    )

    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    for key, expected in {
        "github_actions_run_id": 34491513237,
        "artifact_id": 10157960153,
        "freeze_probe_run_id": 34491513161,
        "freeze_probe_artifact_id": 10157939995,
    }.items():
        _require(int(execution.get(key, 0)), expected, f"{label} execution {key}")
    for key, expected in {
        "workflow_control_head_commit": "aee0f425abf857f8e69e552a9f0b3875c5dc79cb",
        "detector_repo_commit": "e2f78b3addb0a6f7549f8911537c9999b65e3609",
        "artifact_digest_sha256": "b603371a6c94e1dcbf9c966a478d0264f8a0caa0787d062fc275fc7840f6e553",
        "artifact_inner_aggregate_result_sha256": P2_11F_AGGREGATE_SHA256,
        "aggregate_result_sha256": P2_11F_AGGREGATE_SHA256,
        "rules_freeze_sha256": "e1f7908e0e7d5a996a614948b51c4c5b646e5fec0fe9bba6621fbba4f857aac8",
        "freeze_probe_artifact_digest_sha256": "a8f30e04886effbe2813580dab1af66c9263b8ac03ef8bf853e9499c743bfb33",
    }.items():
        _require(execution.get(key), expected, f"{label} execution {key}")

    aggregate_path = legacy._relative_file(repo, execution.get("aggregate_result"), f"{label} aggregate result")
    _require(previous._sha256(aggregate_path), P2_11F_AGGREGATE_SHA256, f"{label} aggregate SHA")
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    _require(aggregate.get("schema"), "breachscope.p2_11f_external_calibration_result.v1", f"{label} aggregate schema")
    _require(aggregate.get("evaluation_class"), "external_calibration", f"{label} aggregate class")
    _require(aggregate.get("detector_repo_commit"), record.get("measurement_repo_commit"), f"{label} aggregate detector")
    _require(aggregate.get("rules_tree_sha256"), to_hash, f"{label} aggregate rule hash")
    _require(int(aggregate.get("rule_file_count", -1)), 4, f"{label} aggregate rule files")
    for key, expected in {
        "rules": 64,
        "events": 902,
        "scenario_hits": 5,
        "scenario_misses": 7,
        "findings": 89,
        "flagged_events": 85,
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
    _require(observed, P2_11F_OUTCOMES, f"{label} outcome map")

    event_level = _mapping(aggregate.get("event_level"), f"{label} event-level boundary")
    _require(event_level.get("labels"), "all_ignore", f"{label} event labels")
    _require(int(event_level.get("scored_events", -1)), 0, f"{label} scored events")
    for key in ("precision", "recall", "false_positive_rate"):
        _require(event_level.get(key), "NOT_CLAIMED", f"{label} event {key}")

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
        "calibration_id": P2_11F_ID,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_rule_hash,
        "to_rules_tree_sha256": to_hash,
        "scenario_hits_before": 4,
        "scenario_hits_after": 5,
        "scenario_total": 12,
        "events": 902,
        "rules": 64,
        "findings": 89,
        "flagged_events": 85,
        "benign_events_scanned": 732200,
        "benign_exact_predicate_matches": 0,
        "record_path": record_path.relative_to(repo).as_posix(),
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = legacy._load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    _require(chain.get("current_evidence_id"), "p2-11f-current-detection-evidence", "current evidence id")
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
            repo, record_path, record, remediation_id, previous_rule_hash, base, previous_attack_hits
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
    _require(calibration_ids, [P2_11D_ID, P2_11E_ID, P2_11F_ID], "calibration chain order/content")

    verified_calibrations: list[dict[str, Any]] = []
    for item in calibrations:
        calibration_id = str(item.get("calibration_id") or "")
        record_path = legacy._relative_file(repo, item.get("measurement_record"), f"{calibration_id} measurement record")
        record = legacy._load_yaml(record_path)
        if calibration_id == P2_11D_ID:
            previous_rule_hash, verified = previous._verify_p2_11d_calibration(
                repo, record_path, record, previous_rule_hash
            )
        elif calibration_id == P2_11E_ID:
            previous_rule_hash, verified = _verify_p2_11e_with_historical_rule_blob(
                repo, record_path, record, previous_rule_hash
            )
        elif calibration_id == P2_11F_ID:
            previous_rule_hash, verified = _verify_p2_11f_calibration(
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
