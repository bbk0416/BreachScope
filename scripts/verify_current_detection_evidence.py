#!/usr/bin/env python3
"""Verify the current detection-evidence chain through P2-11H."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping

import yaml

import verify_current_detection_evidence_p2_11f as previous

legacy = previous.legacy
CHAIN_SCHEMA = previous.CHAIN_SCHEMA
DEFAULT_CHAIN = previous.DEFAULT_CHAIN
CurrentEvidenceError = previous.CurrentEvidenceError

F_ID = previous.P2_11F_ID
G_ID = "p2-11g-t1027-encoded-powershell-mapping"
H_ID = "p2-11h-t1047-wmic-query"
F_HASH = "1626aca8b7b9a8e2a7e1f42360c65b504827ff43e52159eb3716613ebb540a50"
H_HASH = "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
F_RULE_BLOB = previous.P2_11F_RULE_BLOB
H_RULE_BLOB = "0571c33e8d3ab0a7c25ab91a4fb9594a8c2b9c75"
G_AGG_SHA = "5be90a775a2b6f5216a61ab0b061a095797bd302f4480caa6916fef79f83431b"
G_FREEZE_SHA = "73535d68e868b1918a30fddb8ac7678b42908ef96f21d9f6629080eef81a983f"
H_AGG_SHA = "137a445d293f1659a965cd62f2f15a0966b9a1ce375d4a0714ad2f442c11dc1e"
H_FREEZE_SHA = "7ae70b315c92a3a1c2030fb5b787059218216759d7e15350e563eda8dc5961d6"
H_BENIGN_SHA = "33bd265a51625bf104078b7a91ff63a0a83e32606c17af825224d56d2bff2789"


def _require(actual: Any, expected: Any, label: str) -> None:
    previous._require(actual, expected, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    return previous._mapping(value, label)


def _locked_json(repo: Path, value: Any, sha256: str, label: str) -> dict[str, Any]:
    path = legacy._relative_file(repo, value, label)
    _require(previous._sha256(path), sha256, f"{label} SHA")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CurrentEvidenceError(f"{label} must be a JSON object")
    return data


def _verify_history_through_f(repo: Path, chain: Mapping[str, Any]) -> dict[str, Any]:
    """Run the preserved P2-11F verifier against its historical whole-file state."""
    hist = dict(chain)
    hist["current_evidence_id"] = "p2-11f-current-detection-evidence"
    calibrations = chain.get("calibrations")
    if not isinstance(calibrations, list) or len(calibrations) < 3:
        raise CurrentEvidenceError("current chain must contain at least P2-11D/E/F")
    hist["calibrations"] = calibrations[:3]

    original_blob = legacy._git_blob_sha1
    original_tree = legacy.historical._rules_tree_hash

    def historical_blob(path: Path) -> str:
        if Path(path).as_posix().endswith("rules/p2_11_calibration_rules.yml"):
            return F_RULE_BLOB
        return original_blob(path)

    def historical_tree(path: Path) -> tuple[str, int]:
        if Path(path).resolve() == (repo / "rules").resolve():
            return F_HASH, 4
        return original_tree(path)

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8", delete=False) as fh:
            yaml.safe_dump(hist, fh, sort_keys=False, allow_unicode=True)
            tmp_path = Path(fh.name)
        legacy._git_blob_sha1 = historical_blob
        legacy.historical._rules_tree_hash = historical_tree
        result = previous.verify(repo, tmp_path)
    finally:
        legacy._git_blob_sha1 = original_blob
        legacy.historical._rules_tree_hash = original_tree
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
    _require(result.get("status"), "PASS", "P2-11F historical verifier status")
    _require(result.get("current_rules_tree_sha256"), F_HASH, "P2-11F historical rule hash")
    return result


def _verify_g(repo: Path, record: Mapping[str, Any], previous_hash: str) -> dict[str, Any]:
    label = "P2-11G"
    _require(record.get("schema"), "breachscope.p2_11g_mapping_calibration_measurement.v1", f"{label} schema")
    _require(record.get("calibration_id"), G_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("change_class"), "technique_mapping_and_evaluator_semantics_only", f"{label} change class")
    _require(record.get("measurement_repo_commit"), "e876ce32c6b5c9846ca553b03a291548a7a7aa93", f"{label} detector")
    _require(record.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(record.get("to_rules_tree_sha256"), previous_hash, f"{label} unchanged hash")
    _require(record.get("predicate_change"), False, f"{label} predicate change")
    mapping = _mapping(record.get("mapping_change"), f"{label} mapping")
    _require(mapping.get("rule_id"), "R-ENC", f"{label} rule id")
    _require(mapping.get("primary_technique"), "T1059.001", f"{label} primary")
    _require(mapping.get("additional_techniques"), ["T1027.010"], f"{label} secondary")

    cal = _mapping(record.get("external_calibration"), f"{label} calibration")
    for key, expected in {
        "previous_measurement_record": "external_baseline/results/p2_11f_e2f78b3a/measurement.yaml",
        "before_scenario_hits": 5,
        "after_scenario_hits": 6,
        "scenario_misses": 6,
        "scenario_total": 12,
        "events": 902,
        "rules": 64,
        "findings": 89,
        "flagged_events": 85,
    }.items():
        _require(cal.get(key), expected, f"{label} {key}")
    _require(cal.get("changed_scenarios"), ["T1027-2"], f"{label} changed scenarios")

    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    _require(execution.get("github_actions_run_id"), 34499756767, f"{label} run")
    _require(execution.get("artifact_id"), 10161361100, f"{label} artifact")
    _require(execution.get("artifact_digest_sha256"), "2b0f3e8debc4bd72ee8e7d9ed33dcdb487a5111916e7bacdd886e3bc173aefa0", f"{label} artifact digest")
    aggregate = _locked_json(repo, execution.get("aggregate_result"), G_AGG_SHA, f"{label} aggregate")
    _require(aggregate.get("scenario_hits"), 6, f"{label} hits")
    _require(aggregate.get("findings"), 89, f"{label} findings")
    _require(aggregate.get("flagged_events"), 85, f"{label} flagged")
    _require(aggregate.get("rules_tree_sha256"), previous_hash, f"{label} aggregate hash")
    outcomes = {row["scenario_id"]: row["status"] for row in aggregate.get("outcomes", [])}
    _require(outcomes.get("T1027-2"), "hit", f"{label} T1027-2")
    freeze = _locked_json(repo, execution.get("rules_freeze"), G_FREEZE_SHA, f"{label} freeze")
    _require(freeze.get("rules_tree_sha256"), previous_hash, f"{label} freeze hash")

    claims = _mapping(record.get("claim_boundary"), f"{label} claims")
    _require(claims.get("final_blind_holdout"), False, f"{label} blind")
    _require(claims.get("fresh_external_baseline"), False, f"{label} fresh")
    for key in ("production_detection_rate", "production_precision", "production_recall", "production_false_positive_rate"):
        _require(claims.get(key), "NOT_CLAIMED", f"{label} {key}")
    return {
        "calibration_id": G_ID,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": previous_hash,
        "scenario_hits_before": 5,
        "scenario_hits_after": 6,
        "scenario_total": 12,
        "events": 902,
        "rules": 64,
        "findings": 89,
        "flagged_events": 85,
        "predicate_change": False,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def _verify_h(repo: Path, record: Mapping[str, Any], previous_hash: str) -> tuple[str, dict[str, Any]]:
    label = "P2-11H"
    _require(record.get("schema"), "breachscope.p2_11h_external_calibration_measurement.v1", f"{label} schema")
    _require(record.get("calibration_id"), H_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("change_class"), "wmic_query_telemetry_rule_addition", f"{label} change class")
    _require(record.get("measurement_repo_commit"), "7f46b3a29306328716dc02c176b4501eb2ef261b", f"{label} detector")
    _require(record.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(record.get("to_rules_tree_sha256"), H_HASH, f"{label} to hash")

    change = _mapping(record.get("rule_change"), f"{label} rule change")
    _require(change.get("rule_file"), "rules/p2_11_calibration_rules.yml", f"{label} rule file")
    _require(change.get("rule_file_git_blob_sha1"), H_RULE_BLOB, f"{label} recorded rule blob")
    _require(legacy._git_blob_sha1(repo / "rules/p2_11_calibration_rules.yml"), H_RULE_BLOB, f"{label} live rule blob")
    rows = change.get("rules")
    if not isinstance(rows, list) or len(rows) != 1:
        raise CurrentEvidenceError(f"{label} must record exactly one rule")
    row = _mapping(rows[0], f"{label} rule")
    _require(row.get("rule_id"), "R-WMI-QUERY-GET", f"{label} rule id")
    _require(row.get("mitre_technique"), "T1047", f"{label} technique")
    predicate = _mapping(row.get("predicate"), f"{label} predicate")
    _require(predicate.get("source_equals"), "Microsoft-Windows-Sysmon", f"{label} source")
    _require(str(predicate.get("event_id_equals")), "1", f"{label} event id")
    _require(predicate.get("image_endswith"), r"\wmic.exe", f"{label} image")
    expected_regex = r"^(?!.*\/format\s*:\s*.*https?:\/\/).*\bget\b"
    _require(predicate.get("command_line_regex"), expected_regex, f"{label} command regex")
    live = legacy._load_rule(repo, "rules/p2_11_calibration_rules.yml", "R-WMI-QUERY-GET")
    for key, expected in {
        "field": "command_line",
        "operator": "regex",
        "pattern": expected_regex,
        "severity": "low",
        "mitre_technique": "T1047",
    }.items():
        _require(str(live.get(key)), expected, f"{label} live {key}")

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign")
    _require(benign.get("corpus_sha256"), "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e", f"{label} corpus")
    for key, expected in {"sysmon_records": 732200, "sysmon_chunks": 11894, "sysmon_event1": 2149, "parse_errors": 0}.items():
        _require(benign.get(key), expected, f"{label} benign {key}")
    for key in ("wmic_event1", "wmic_get_any", "wmic_get_non_remote_xsl", "wmic_useraccount_get", "wmic_process_get", "wmic_user_or_process_get", "wmic_get_format_csv", "wmic_get_remote_format_http"):
        _require(benign.get(key), 0, f"{label} benign {key}")
    _require(benign.get("probe_run_id"), 34554436633, f"{label} probe run")
    _require(benign.get("artifact_id"), 10182076804, f"{label} benign artifact")
    stored_benign = _locked_json(repo, benign.get("stored_result"), H_BENIGN_SHA, f"{label} benign stored")
    for value in stored_benign.get("candidate_counts", {}).values():
        _require(value, 0, f"{label} stored benign candidate")

    cal = _mapping(record.get("external_calibration"), f"{label} calibration")
    for key, expected in {
        "previous_measurement_record": "external_baseline/results/p2_11g_e876ce32/measurement.yaml",
        "before_scenario_hits": 6,
        "after_scenario_hits": 8,
        "scenario_misses": 4,
        "scenario_total": 12,
        "events": 902,
        "rules": 65,
        "findings": 91,
        "flagged_events": 87,
    }.items():
        _require(cal.get(key), expected, f"{label} {key}")
    _require(cal.get("changed_scenarios"), ["T1047-1", "T1047-2"], f"{label} changed scenarios")
    _require(cal.get("remaining_miss_scenarios"), ["T1003-1", "T1003-2", "T1021.001-1", "T1021.001-2"], f"{label} misses")

    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    _require(execution.get("github_actions_run_id"), 34555286447, f"{label} run")
    _require(execution.get("artifact_id"), 10182325376, f"{label} artifact")
    _require(execution.get("artifact_digest_sha256"), "420df5a561b6d50489119bffa794d07ddbb94551cda77e8dc9d3b91fbdfcf0fd", f"{label} artifact digest")
    _require(execution.get("freeze_probe_run_id"), 34555286457, f"{label} freeze run")
    _require(execution.get("freeze_probe_artifact_id"), 10182311143, f"{label} freeze artifact")
    aggregate = _locked_json(repo, execution.get("aggregate_result"), H_AGG_SHA, f"{label} aggregate")
    for key, expected in {"scenario_hits": 8, "scenario_misses": 4, "scenario_total": 12, "events": 902, "rules": 65, "findings": 91, "flagged_events": 87}.items():
        _require(aggregate.get(key), expected, f"{label} aggregate {key}")
    _require(aggregate.get("rules_tree_sha256"), H_HASH, f"{label} aggregate hash")
    outcomes = {row["scenario_id"]: row["status"] for row in aggregate.get("outcomes", [])}
    _require([key for key in ("T1047-1", "T1047-2") if outcomes.get(key) == "hit"], ["T1047-1", "T1047-2"], f"{label} new hits")
    freeze = _locked_json(repo, execution.get("rules_freeze"), H_FREEZE_SHA, f"{label} freeze")
    _require(freeze.get("repo_commit"), record.get("measurement_repo_commit"), f"{label} freeze commit")
    _require(freeze.get("rules_tree_sha256"), H_HASH, f"{label} freeze hash")
    _require(freeze.get("rule_file_count"), 4, f"{label} freeze file count")

    event_level = _mapping(aggregate.get("event_level"), f"{label} event level")
    _require(event_level.get("labels"), "all_ignore", f"{label} labels")
    _require(event_level.get("scored_events"), 0, f"{label} scored events")
    for key in ("precision", "recall", "false_positive_rate"):
        _require(event_level.get(key), "NOT_CLAIMED", f"{label} event {key}")
    claims = _mapping(record.get("claim_boundary"), f"{label} claims")
    _require(claims.get("final_blind_holdout"), False, f"{label} blind")
    _require(claims.get("fresh_external_baseline"), False, f"{label} fresh")
    for key in ("production_detection_rate", "production_precision", "production_recall", "production_false_positive_rate", "fresh_full_benign_fpr_for_new_rulepack"):
        _require(claims.get(key), "NOT_CLAIMED", f"{label} {key}")

    return H_HASH, {
        "calibration_id": H_ID,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": H_HASH,
        "scenario_hits_before": 6,
        "scenario_hits_after": 8,
        "scenario_total": 12,
        "events": 902,
        "rules": 65,
        "findings": 91,
        "flagged_events": 87,
        "benign_events_scanned": 732200,
        "benign_exact_predicate_matches": 0,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = legacy._load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    _require(chain.get("current_evidence_id"), "p2-11h-current-detection-evidence", "current evidence id")
    calibrations = chain.get("calibrations")
    if not isinstance(calibrations, list):
        raise CurrentEvidenceError("calibrations must be a list")
    expected_ids = [previous.P2_11D_ID, previous.P2_11E_ID, F_ID, G_ID, H_ID]
    _require([row.get("calibration_id") for row in calibrations], expected_ids, "calibration chain order/content")

    history = _verify_history_through_f(repo, chain)
    g_path = legacy._relative_file(repo, calibrations[3].get("measurement_record"), "P2-11G measurement")
    g_record = legacy._load_yaml(g_path)
    g = _verify_g(repo, g_record, F_HASH)
    h_path = legacy._relative_file(repo, calibrations[4].get("measurement_record"), "P2-11H measurement")
    h_record = legacy._load_yaml(h_path)
    final_hash, h = _verify_h(repo, h_record, F_HASH)

    current_hash, rule_file_count = legacy.historical._rules_tree_hash(repo / "rules")
    _require(final_hash, current_hash, "current rule tree explained by chain")
    claims = _mapping(chain.get("claim_boundary"), "current evidence claims")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", "production accuracy")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", "production FPR")
    _require(claims.get("final_blind_holdout"), False, "final blind holdout")
    _require(claims.get("fresh_full_benign_fpr_for_current_rulepack"), "NOT_CLAIMED", "fresh full benign FPR")

    return {
        "schema": "breachscope.current_detection_evidence_verification.v4",
        "current_evidence_id": chain.get("current_evidence_id"),
        "status": "PASS",
        "base_rules_tree_sha256": history["base_rules_tree_sha256"],
        "current_rules_tree_sha256": current_hash,
        "rule_file_count": rule_file_count,
        "base_attack_scenario_hits": history["base_attack_scenario_hits"],
        "current_attack_scenario_hits": history["current_attack_scenario_hits"],
        "attack_scenario_total": history["attack_scenario_total"],
        "historical_benign": history["historical_benign"],
        "remediations": history["remediations"],
        "calibrations": [*history["calibrations"], g, h],
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
        print(f"Current rules SHA-256: {result['current_rules_tree_sha256']}")
        for calibration in result["calibrations"]:
            print(f"{calibration['calibration_id']}: {calibration['scenario_hits_before']}/{calibration['scenario_total']} -> {calibration['scenario_hits_after']}/{calibration['scenario_total']}")
        print("Fresh full benign FPR for current rulepack: NOT CLAIMED")
        print("Production accuracy/FPR: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
