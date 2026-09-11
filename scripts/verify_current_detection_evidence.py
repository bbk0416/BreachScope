#!/usr/bin/env python3
"""Verify the current detection-evidence chain through P2-11J."""
from __future__ import annotations

import argparse
import hashlib
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

J_ID = "p2-11j-t1003-networkprovider-credential-capture"
H_HASH = "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
J_HASH = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
H_RULE_BLOB = "0571c33e8d3ab0a7c25ab91a4fb9594a8c2b9c75"
J_RULE_BLOB = "aa6e24f5117dbbcacf11a844aae4cc66dec9613c"
J_AGG_SHA = "82cd205ac90b17d72a947448418d17382926967c1cf801a0882745900c03a0f7"
J_FREEZE_SHA = "9975bdbc0efcf31d7a7a92c7cb28f4e9186704f0660282abc603c61d10cee5fc"
J_BENIGN_SHA = "4942c9782ade6c2dc1148a214efc54db4579ba219d3196dfa52bf1a6b08f8b65"


def _require(actual: Any, expected: Any, label: str) -> None:
    previous._require(actual, expected, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    return previous._mapping(value, label)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _locked_json(repo: Path, value: Any, sha256: str, label: str) -> dict[str, Any]:
    path = legacy._relative_file(repo, value, label)
    _require(_sha256(path), sha256, f"{label} SHA")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CurrentEvidenceError(f"{label} must be a JSON object")
    return data


def _verify_history_through_h(repo: Path, chain: Mapping[str, Any]) -> dict[str, Any]:
    hist = dict(chain)
    hist["current_evidence_id"] = "p2-11h-current-detection-evidence"
    calibrations = chain.get("calibrations")
    if not isinstance(calibrations, list) or len(calibrations) < 5:
        raise CurrentEvidenceError("current chain must contain P2-11D through P2-11H")
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


def _verify_j(repo: Path, record: Mapping[str, Any], previous_hash: str) -> tuple[str, dict[str, Any]]:
    label = "P2-11J"
    _require(record.get("schema"), "breachscope.p2_11j_external_calibration_measurement.v1", f"{label} schema")
    _require(record.get("calibration_id"), J_ID, f"{label} id")
    _require(record.get("measurement_class"), "external_calibration", f"{label} class")
    _require(record.get("change_class"), "networkprovider_credential_capture_setup_rule_addition", f"{label} change class")
    _require(record.get("measurement_repo_commit"), "357b7ea88c5949d899ec637c95f56bad61605f3c", f"{label} detector")
    _require(record.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(record.get("to_rules_tree_sha256"), J_HASH, f"{label} to hash")

    change = _mapping(record.get("rule_change"), f"{label} rule change")
    _require(change.get("rule_file"), "rules/p2_11_calibration_rules.yml", f"{label} rule file")
    _require(change.get("rule_file_git_blob_sha1"), J_RULE_BLOB, f"{label} recorded rule blob")
    _require(legacy._git_blob_sha1(repo / "rules/p2_11_calibration_rules.yml"), J_RULE_BLOB, f"{label} live rule blob")
    rows = change.get("rules")
    if not isinstance(rows, list) or len(rows) != 1:
        raise CurrentEvidenceError(f"{label} must record exactly one rule")
    row = _mapping(rows[0], f"{label} rule")
    _require(row.get("rule_id"), "R-NETWORK-PROVIDER-CREDENTIAL-CAPTURE-SETUP", f"{label} rule id")
    _require(row.get("mitre_technique"), "T1003", f"{label} technique")
    predicate = _mapping(row.get("predicate"), f"{label} predicate")
    expected_predicate = {
        "source_equals": "Microsoft-Windows-Sysmon",
        "event_id_equals": "1",
        "command_line_order_path_regex": r"\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order",
        "command_line_providerorder_regex": r"\bProviderOrder\b",
        "command_line_service_networkprovider_regex": r"\\SYSTEM\\CurrentControlSet\\Services\\[^\\\s\"]+\\NetworkProvider",
        "command_line_providerpath_regex": r"\bProviderPath\b",
    }
    for key, expected in expected_predicate.items():
        _require(str(predicate.get(key)), expected, f"{label} predicate {key}")

    live = legacy._load_rule(repo, "rules/p2_11_calibration_rules.yml", "R-NETWORK-PROVIDER-CREDENTIAL-CAPTURE-SETUP")
    for key, expected in {
        "field": "command_line",
        "operator": "regex",
        "pattern": r"\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order",
        "severity": "medium",
        "mitre_technique": "T1003",
    }.items():
        _require(str(live.get(key)), expected, f"{label} live {key}")

    benign = _mapping(record.get("benign_incremental_match_proof"), f"{label} benign")
    _require(benign.get("corpus_sha256"), "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e", f"{label} corpus")
    for key, expected in {"sysmon_records": 732200, "sysmon_chunks": 11894, "sysmon_event1": 2149, "parse_errors": 0}.items():
        _require(benign.get(key), expected, f"{label} benign {key}")
    candidate_keys = (
        "networkprovider_any",
        "networkprovider_order",
        "providerorder",
        "setitem_providerorder",
        "service_networkprovider",
        "service_providerpath",
        "order_and_service_providerpath",
    )
    for key in candidate_keys:
        _require(benign.get(key), 0, f"{label} benign {key}")
    _require(benign.get("probe_run_id"), 34599085112, f"{label} probe run")
    _require(benign.get("probe_commit"), "2b20c6e56e7e0938fa5c9db25266fa402afc6961", f"{label} probe commit")
    _require(benign.get("artifact_id"), 10263218975, f"{label} benign artifact")
    _require(benign.get("artifact_digest_sha256"), "3379ce899268e50c20839436e7eaf269f7f4bc66262a8c526e87f0da35f13b90", f"{label} benign artifact digest")
    stored_benign = _locked_json(repo, benign.get("stored_result"), J_BENIGN_SHA, f"{label} benign stored")
    for key in candidate_keys:
        _require(stored_benign.get("candidate_counts", {}).get(key), 0, f"{label} stored benign {key}")

    cal = _mapping(record.get("external_calibration"), f"{label} calibration")
    for key, expected in {
        "previous_measurement_record": "external_baseline/results/p2_11h_7f46b3a2/measurement.yaml",
        "before_scenario_hits": 8,
        "after_scenario_hits": 9,
        "scenario_misses": 3,
        "scenario_total": 12,
        "events": 902,
        "rules": 66,
        "findings": 92,
        "flagged_events": 88,
    }.items():
        _require(cal.get(key), expected, f"{label} {key}")
    _require(cal.get("changed_scenarios"), ["T1003-2"], f"{label} changed scenarios")
    _require(cal.get("remaining_miss_scenarios"), ["T1003-1", "T1021.001-1", "T1021.001-2"], f"{label} misses")

    execution = _mapping(record.get("measurement_execution"), f"{label} execution")
    _require(execution.get("github_actions_run_id"), 34600156570, f"{label} run")
    _require(execution.get("workflow_control_head_commit"), "a81dd2fae4c6bd39c21f64a3bf81b3bc5d48b491", f"{label} control")
    _require(execution.get("artifact_id"), 10264215439, f"{label} artifact")
    _require(execution.get("artifact_digest_sha256"), "abe3055f7a2cfc636278539e47f97ca5308f0f38487c7e046d0d9c7dc45c07c2", f"{label} artifact digest")
    _require(execution.get("freeze_probe_run_id"), 34600156592, f"{label} freeze run")
    _require(execution.get("freeze_probe_artifact_id"), 10263483514, f"{label} freeze artifact")
    _require(execution.get("freeze_probe_artifact_digest_sha256"), "e616268c218a0fc9f71f82c95e01b1b06741f5a23926e8caf56fcb5dfb25460a", f"{label} freeze digest")

    aggregate = _locked_json(repo, execution.get("aggregate_result"), J_AGG_SHA, f"{label} aggregate")
    for key, expected in {"scenario_hits": 9, "scenario_misses": 3, "scenario_total": 12, "events": 902, "rules": 66, "findings": 92, "flagged_events": 88}.items():
        _require(aggregate.get(key), expected, f"{label} aggregate {key}")
    _require(aggregate.get("rules_tree_sha256"), J_HASH, f"{label} aggregate hash")
    outcomes = {row["scenario_id"]: row["status"] for row in aggregate.get("outcomes", [])}
    _require(outcomes.get("T1003-2"), "hit", f"{label} T1003-2")
    _require([key for key, value in outcomes.items() if value == "miss"], ["T1003-1", "T1021.001-1", "T1021.001-2"], f"{label} remaining misses")

    freeze = _locked_json(repo, execution.get("rules_freeze"), J_FREEZE_SHA, f"{label} freeze")
    _require(freeze.get("repo_commit"), record.get("measurement_repo_commit"), f"{label} freeze commit")
    _require(freeze.get("rules_tree_sha256"), J_HASH, f"{label} freeze hash")
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

    return J_HASH, {
        "calibration_id": J_ID,
        "measurement_repo_commit": record.get("measurement_repo_commit"),
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": J_HASH,
        "scenario_hits_before": 8,
        "scenario_hits_after": 9,
        "scenario_total": 12,
        "events": 902,
        "rules": 66,
        "findings": 92,
        "flagged_events": 88,
        "benign_events_scanned": 732200,
        "benign_exact_predicate_matches": 0,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = legacy._load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    _require(chain.get("current_evidence_id"), "p2-11j-current-detection-evidence", "current evidence id")
    calibrations = chain.get("calibrations")
    if not isinstance(calibrations, list):
        raise CurrentEvidenceError("calibrations must be a list")
    expected_ids = [
        previous.previous.P2_11D_ID,
        previous.previous.P2_11E_ID,
        previous.F_ID,
        previous.G_ID,
        previous.H_ID,
        J_ID,
    ]
    _require([row.get("calibration_id") for row in calibrations], expected_ids, "calibration chain order/content")

    history = _verify_history_through_h(repo, chain)
    j_path = legacy._relative_file(repo, calibrations[5].get("measurement_record"), "P2-11J measurement")
    j_record = legacy._load_yaml(j_path)
    final_hash, j = _verify_j(repo, j_record, H_HASH)

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
        "calibrations": [*history["calibrations"], j],
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
