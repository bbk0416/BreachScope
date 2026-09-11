#!/usr/bin/env python3
"""Verify the current detection-evidence chain through P2-11I."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, Mapping

import yaml

import verify_current_detection_evidence_p2_11h as previous

legacy = previous.legacy
CHAIN_SCHEMA = previous.CHAIN_SCHEMA
DEFAULT_CHAIN = previous.DEFAULT_CHAIN
CurrentEvidenceError = previous.CurrentEvidenceError

I_ID = "p2-11i-t1021-001-rdp-client"
H_HASH = "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
I_HASH = "655f41d452a570938ff444b0d0ab156db1cf2267d1c8cb6c6b5544c8e57bfd32"
H_RULE_BLOB = "0571c33e8d3ab0a7c25ab91a4fb9594a8c2b9c75"
I_RULE_BLOB = "bb30b54a4f05fe794d3abd03ddaa898604e5f4be"
I_AGG_SHA = "1c888935f9e7434c2e7d4e048b35eca1ad18fe47bb32707c445dc901d4324cb1"
I_FREEZE_SHA = "aa946b2d0601b9ab2423092691f1ec34d83cc9102ba8129ef39d3e18973645ec"
I_BENIGN_SHA = "1004b0242fd73ef6d60aba85d31df89b6540372f76aba22e6fb5dccb929788c0"


def _require(actual: Any, expected: Any, label: str) -> None:
    previous._require(actual, expected, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    return previous._mapping(value, label)


def _locked_json(repo: Path, value: Any, sha256: str, label: str) -> dict[str, Any]:
    path = legacy._relative_file(repo, value, label)
    _require(previous.previous._sha256(path), sha256, f"{label} SHA")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CurrentEvidenceError(f"{label} must be a JSON object")
    return data


def _verify_history_through_h(repo: Path, chain: Mapping[str, Any]) -> dict[str, Any]:
    """Run the preserved P2-11H verifier against its historical whole-file state."""
    hist = dict(chain)
    hist["current_evidence_id"] = "p2-11h-current-detection-evidence"
    calibrations = chain.get("calibrations")
    if not isinstance(calibrations, list) or len(calibrations) < 5:
        raise CurrentEvidenceError("current chain must contain at least P2-11D through P2-11H")
    hist["calibrations"] = calibrations[:5]

    original_blob = legacy._git_blob_sha1
    original_tree = legacy.historical._rules_tree_hash

    def historical_blob(path: Path) -> str:
        if Path(path).as_posix().endswith("rules/p2_11_calibration_rules.yml"):
            return H_RULE_BLOB
        return original_blob(path)

    def historical_tree(path: Path) -> tuple[str, int]:
        if Path(path).resolve() == (repo / "rules").resolve():
            return H_HASH, 4
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

    _require(result.get("status"), "PASS", "P2-11H historical verifier status")
    _require(result.get("current_rules_tree_sha256"), H_HASH, "P2-11H historical rule hash")
    return result


def _verify_i(repo: Path, record: Mapping[str, Any], previous_hash: str) -> tuple[str, dict[str, Any]]:
    label = "P2-11I"
    _require(record.get("schema"), "breachscope.p2_11i_external_calibration_measurement.v1", f"{label} schema")
    _require(record.get("calibration_id"), I_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("change_class"), "rdp_client_mstsc_v_telemetry_rule_addition", f"{label} change class")
    _require(record.get("measurement_repo_commit"), "454671dd38f6c628dfe726929e31c83d7ae65204", f"{label} detector")
    _require(record.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(record.get("to_rules_tree_sha256"), I_HASH, f"{label} to hash")

    change = _mapping(record.get("rule_change"), f"{label} rule change")
    _require(change.get("rule_file"), "rules/p2_11_calibration_rules.yml", f"{label} rule file")
    _require(change.get("rule_file_git_blob_sha1"), I_RULE_BLOB, f"{label} recorded rule blob")
    _require(legacy._git_blob_sha1(repo / "rules/p2_11_calibration_rules.yml"), I_RULE_BLOB, f"{label} live rule blob")
    rows = change.get("rules")
    if not isinstance(rows, list) or len(rows) != 1:
        raise CurrentEvidenceError(f"{label} must record exactly one rule")
    row = _mapping(rows[0], f"{label} rule")
    _require(row.get("rule_id"), "R-RDP-CLIENT-MSTSC-V", f"{label} rule id")
    _require(row.get("mitre_technique"), "T1021.001", f"{label} technique")
    predicate = _mapping(row.get("predicate"), f"{label} predicate")
    _require(predicate.get("source_equals"), "Microsoft-Windows-Sysmon", f"{label} source")
    _require(str(predicate.get("event_id_equals")), "1", f"{label} event id")
    _require(predicate.get("image_endswith"), r"\mstsc.exe", f"{label} image")
    expected_regex = r'(?i)(?:^|\s)/v\s*:\s*(?:"[^"]+"|\S+)'
    _require(predicate.get("command_line_regex"), expected_regex, f"{label} command regex")

    live = legacy._load_rule(repo, "rules/p2_11_calibration_rules.yml", "R-RDP-CLIENT-MSTSC-V")
    for key, expected in {
        "field": "command_line",
        "operator": "regex",
        "pattern": expected_regex,
        "severity": "low",
        "mitre_technique": "T1021.001",
    }.items():
        _require(str(live.get(key)), expected, f"{label} live {key}")

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign")
    _require(benign.get("corpus_sha256"), "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e", f"{label} corpus")
    for key, expected in {"sysmon_records": 732200, "sysmon_chunks": 11894, "sysmon_event1": 2149, "parse_errors": 0}.items():
        _require(benign.get(key), expected, f"{label} benign {key}")
    for key in ("mstsc_event1", "mstsc_v", "mstsc_v_admin", "mstsc_v_restrictedadmin"):
        _require(benign.get(key), 0, f"{label} benign {key}")
    _require(benign.get("probe_run_id"), 34559208746, f"{label} probe run")
    _require(benign.get("probe_commit"), "bcf405c635aefcff41c97b83003d149262c5c9a7", f"{label} probe commit")
    _require(benign.get("artifact_id"), 10183769008, f"{label} benign artifact")
    _require(benign.get("artifact_digest_sha256"), "c81c8c311538a1e2e34fba516d259ab37f28069bebd17c1d978451095639e986", f"{label} benign digest")
    stored_benign = _locked_json(repo, benign.get("stored_result"), I_BENIGN_SHA, f"{label} benign stored")
    for value in stored_benign.get("candidate_counts", {}).values():
        _require(value, 0, f"{label} stored benign candidate")

    cal = _mapping(record.get("external_calibration"), f"{label} calibration")
    for key, expected in {
        "previous_measurement_record": "external_baseline/results/p2_11h_7f46b3a2/measurement.yaml",
        "before_scenario_hits": 8,
        "after_scenario_hits": 8,
        "scenario_misses": 4,
        "scenario_total": 12,
        "events": 902,
        "rules": 66,
        "findings": 91,
        "flagged_events": 87,
    }.items():
        _require(cal.get(key), expected, f"{label} {key}")
    _require(cal.get("changed_scenarios"), [], f"{label} changed scenarios")
    _require(cal.get("remaining_miss_scenarios"), ["T1003-1", "T1003-2", "T1021.001-1", "T1021.001-2"], f"{label} misses")

    observation = _mapping(record.get("scenario_observation"), f"{label} observation")
    _require(observation.get("scenario_id"), "T1021.001-1", f"{label} observation scenario")
    _require(observation.get("diagnostic_run_id"), 34563783591, f"{label} diagnostic run")
    _require(observation.get("diagnostic_head_commit"), "cc6e91036b9412008208141bfe6440a46c6e269a", f"{label} diagnostic head")
    _require(observation.get("sysmon_records"), 79, f"{label} observed sysmon")
    _require(observation.get("matching_context_records"), 3, f"{label} context records")
    _require(observation.get("captured_mstsc_record_index"), 35, f"{label} mstsc record")
    _require(observation.get("captured_mstsc_command_line"), r'"C:\Windows\system32\mstsc.exe" /v:', f"{label} mstsc command")
    _require(observation.get("captured_target_present"), False, f"{label} target present")

    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    _require(execution.get("github_actions_run_id"), 34560449688, f"{label} run")
    _require(execution.get("workflow_control_head_commit"), "5152dbc66219830ca7f5fc1cb73145778d4383c7", f"{label} control")
    _require(execution.get("detector_repo_commit"), "454671dd38f6c628dfe726929e31c83d7ae65204", f"{label} execution detector")
    _require(execution.get("artifact_id"), 10184128874, f"{label} artifact")
    _require(execution.get("artifact_digest_sha256"), "4ef25e6ce8fb68b7555efd77d63d36e37747703394fc48ea99d886fe9ec66e5c", f"{label} artifact digest")
    _require(execution.get("freeze_probe_run_id"), 34560449678, f"{label} freeze run")
    _require(execution.get("freeze_probe_artifact_id"), 10184116507, f"{label} freeze artifact")
    _require(execution.get("freeze_probe_artifact_digest_sha256"), "ea1a89f40d442b3579687fdfaafc9fe66204b0711d8c011a5b08ed011fd20bcd", f"{label} freeze digest")

    aggregate = _locked_json(repo, execution.get("aggregate_result"), I_AGG_SHA, f"{label} aggregate")
    for key, expected in {"scenario_hits": 8, "scenario_misses": 4, "scenario_total": 12, "events": 902, "rules": 66, "findings": 91, "flagged_events": 87}.items():
        _require(aggregate.get(key), expected, f"{label} aggregate {key}")
    _require(aggregate.get("rules_tree_sha256"), I_HASH, f"{label} aggregate hash")
    outcomes = {row["scenario_id"]: row["status"] for row in aggregate.get("outcomes", [])}
    _require(outcomes.get("T1021.001-1"), "miss", f"{label} T1021.001-1 status")
    _require(outcomes.get("T1021.001-2"), "miss", f"{label} T1021.001-2 status")

    freeze = _locked_json(repo, execution.get("rules_freeze"), I_FREEZE_SHA, f"{label} freeze")
    _require(freeze.get("repo_commit"), record.get("measurement_repo_commit"), f"{label} freeze commit")
    _require(freeze.get("rules_tree_sha256"), I_HASH, f"{label} freeze hash")
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

    return I_HASH, {
        "calibration_id": I_ID,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": I_HASH,
        "scenario_hits_before": 8,
        "scenario_hits_after": 8,
        "scenario_total": 12,
        "events": 902,
        "rules": 66,
        "findings": 91,
        "flagged_events": 87,
        "benign_events_scanned": 732200,
        "benign_exact_predicate_matches": 0,
        "calibration_gain": 0,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = legacy._load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    _require(chain.get("current_evidence_id"), "p2-11i-current-detection-evidence", "current evidence id")
    calibrations = chain.get("calibrations")
    if not isinstance(calibrations, list):
        raise CurrentEvidenceError("calibrations must be a list")
    expected_ids = [previous.previous.P2_11D_ID, previous.previous.P2_11E_ID, previous.F_ID, previous.G_ID, previous.H_ID, I_ID]
    _require([row.get("calibration_id") for row in calibrations], expected_ids, "calibration chain order/content")

    history = _verify_history_through_h(repo, chain)
    i_path = legacy._relative_file(repo, calibrations[5].get("measurement_record"), "P2-11I measurement")
    i_record = legacy._load_yaml(i_path)
    final_hash, i = _verify_i(repo, i_record, H_HASH)

    current_hash, rule_file_count = legacy.historical._rules_tree_hash(repo / "rules")
    _require(final_hash, current_hash, "current rule tree explained by chain")
    claims = _mapping(chain.get("claim_boundary"), "current evidence claims")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", "production accuracy")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", "production FPR")
    _require(claims.get("final_blind_holdout"), False, "final blind holdout")
    _require(claims.get("fresh_full_benign_fpr_for_current_rulepack"), "NOT_CLAIMED", "fresh full benign FPR")

    return {
        "schema": "breachscope.current_detection_evidence_verification.v5",
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
        "calibrations": [*history["calibrations"], i],
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
