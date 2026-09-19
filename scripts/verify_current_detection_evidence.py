#!/usr/bin/env python3
"""Verify the current detection-evidence chain through P2-20."""
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

P20_ID = "p2-20-postholdout-coverage"
P20_HASH = "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
P20_RULE_BLOB = "1b5d6490a0cb2509550b84c4bb538eda89d3e687"
P20_INGEST_BLOB = "42ce35bff10d0541d26e0a5181cfcd1ef9a459cc"
P20_RAW_SHA = "b4412e482500c38a72b894f7ddf0bac6f1f3cb8657db132b67e771966e486846"
P20_COMMIT = "73a9bc81c3bea4836d3a7301beeadf236d9f1b8d"

P24D_ID = "p2-24d-rule-noise-remediation"
P24D_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
P24D_RULE_BLOB = "ef1e026256eb1e66f992459166ede963424606df"
P24D_COMMIT = "66f5d2e0061ea34113038a712597113a6df7bd63"

P25_ID = "p2-25-deepbluecli-fresh-attack"
P25_RESULT_SHA = "be56514a196551904f32cd2bd829912cd13ae3bd4a2ce4cc28f268dceca9f664"
P25_RULE_HASH = P24D_HASH



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


def _verify_p2_20(
    repo: Path,
    record: Mapping[str, Any],
    previous_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "P2-20"
    _require(
        record.get("schema"),
        "breachscope.p2_20_postholdout_calibration_measurement.v1",
        f"{label} schema",
    )
    _require(record.get("calibration_id"), P20_ID, f"{label} id")
    _require(record.get("measurement_class"), "post_holdout_calibration", f"{label} class")
    _require(
        record.get("change_class"),
        "attack_data_record_framing_and_command_rule_addition",
        f"{label} change class",
    )
    _require(record.get("measurement_repo_commit"), P20_COMMIT, f"{label} commit")
    _require(record.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(record.get("to_rules_tree_sha256"), P20_HASH, f"{label} to hash")

    change = _mapping(record.get("rule_change"), f"{label} rule change")
    _require(change.get("rule_file"), "rules/p2_20_postholdout_rules.yml", f"{label} rule file")
    _require(change.get("rule_file_git_blob_sha1"), P20_RULE_BLOB, f"{label} rule blob")
    _require(
        legacy._git_blob_sha1(repo / "rules/p2_20_postholdout_rules.yml"),
        P20_RULE_BLOB,
        f"{label} live rule blob",
    )
    expected_rules = {
        "R-WINRS-REMOTE-TARGET": ("T1021.006", "medium"),
        "R-DOMAIN-ACCOUNT-DISCOVERY-CMD": ("T1087.002", "low"),
    }
    rows = change.get("added_rules")
    if not isinstance(rows, list) or len(rows) != 2:
        raise CurrentEvidenceError(f"{label} must record exactly two added rules")
    _require(
        {row.get("rule_id"): row.get("mitre_technique") for row in rows},
        {key: value[0] for key, value in expected_rules.items()},
        f"{label} recorded rules",
    )
    for rule_id, (technique, severity) in expected_rules.items():
        live = legacy._load_rule(repo, "rules/p2_20_postholdout_rules.yml", rule_id)
        _require(live.get("field"), "command_line", f"{label} {rule_id} field")
        _require(live.get("operator"), "regex", f"{label} {rule_id} operator")
        _require(live.get("mitre_technique"), technique, f"{label} {rule_id} technique")
        _require(live.get("severity"), severity, f"{label} {rule_id} severity")
        predicates = {
            (item.get("field"), str(item.get("pattern")))
            for item in (live.get("all_of") or [])
            if isinstance(item, Mapping)
        }
        _require(("event_id", "1") in predicates, True, f"{label} {rule_id} event predicate")
        _require(
            ("source", "Microsoft-Windows-Sysmon") in predicates,
            True,
            f"{label} {rule_id} source predicate",
        )

    parser = _mapping(record.get("parser_change"), f"{label} parser change")
    _require(parser.get("file"), "breachscope/ingest.py", f"{label} parser file")
    _require(parser.get("git_blob_sha1"), P20_INGEST_BLOB, f"{label} parser blob")
    _require(
        legacy._git_blob_sha1(repo / "breachscope/ingest.py"),
        P20_INGEST_BLOB,
        f"{label} live parser blob",
    )
    _require(parser.get("helper"), "iter_event_xml_records", f"{label} parser helper")
    source = (repo / "breachscope/ingest.py").read_text(encoding="utf-8")
    _require("def iter_event_xml_records(" in source, True, f"{label} parser helper source")

    raw_spec = _mapping(record.get("raw_measurement"), f"{label} raw measurement")
    _require(raw_spec.get("sha256"), P20_RAW_SHA, f"{label} raw SHA record")
    raw = _locked_json(repo, raw_spec.get("path"), P20_RAW_SHA, f"{label} raw")
    _require(raw.get("product_commit"), P20_COMMIT, f"{label} raw product")
    _require(raw.get("rules_tree_sha256"), P20_HASH, f"{label} raw rules")
    _require(raw.get("rule_count"), 68, f"{label} raw rule count")
    attack = _mapping(raw.get("attack_summary"), f"{label} attack summary")
    for key, expected in {
        "dataset_hits": 5,
        "dataset_total": 5,
        "total_events": 21328,
        "total_parse_errors": 0,
    }.items():
        _require(attack.get(key), expected, f"{label} attack {key}")

    benign = _mapping(raw.get("benign_probe"), f"{label} benign")
    for key, expected in {
        "raw_wevtutil_event1_records": 2323,
        "parsed_events": 2323,
        "parse_errors": 0,
        "new_rule_findings": 0,
        "historical_p2_13_binding_sysmon_event1": 2302,
    }.items():
        _require(benign.get(key), expected, f"{label} benign {key}")

    claims = _mapping(record.get("claim_boundary"), f"{label} claims")
    _require(claims.get("attack_independent_holdout"), False, f"{label} independent")
    _require(claims.get("attack_result_is_posthoc"), True, f"{label} posthoc")
    for key in (
        "production_precision",
        "production_recall",
        "production_false_positive_rate",
        "fresh_full_benign_fpr_for_new_rulepack",
    ):
        _require(claims.get(key), "NOT_CLAIMED", f"{label} {key}")
    _require(claims.get("p2_14e_final_blind_holdout_rerun"), False, f"{label} P2-14E rerun")
    _require(claims.get("p2_14e_artifacts_modified"), False, f"{label} P2-14E modified")

    return P20_HASH, {
        "calibration_id": P20_ID,
        "measurement_repo_commit": P20_COMMIT,
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": P20_HASH,
        "dataset_hits_before": 1,
        "dataset_hits_after": 5,
        "dataset_total": 5,
        "attack_result_is_posthoc": True,
        "events": 21328,
        "rules": 68,
        "parse_errors": 0,
        "benign_events_scanned": 2323,
        "benign_exact_predicate_matches": 0,
        "fresh_full_benign_fpr_for_new_rulepack": "NOT_CLAIMED",
    }


def _verify_p2_24d(
    repo: Path,
    record: Mapping[str, Any],
    previous_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "P2-24D"
    _require(
        record.get("schema"),
        "breachscope.p2_24d_posthoc_rule_noise_diagnosis.v1",
        f"{label} schema",
    )
    _require(record.get("analysis_id"), "p2-24d-posthoc-rule-noise-diagnosis", f"{label} id")
    _require(
        record.get("analysis_class"),
        "POST_HOC_DIAGNOSTIC_NOT_FRESH_EVALUATION",
        f"{label} class",
    )

    remediation = _mapping(record.get("remediation"), f"{label} remediation")
    _require(remediation.get("remediation_id"), P24D_ID, f"{label} remediation id")
    _require(
        remediation.get("change_class"),
        "posthoc_benign_noise_narrowing",
        f"{label} change class",
    )
    _require(remediation.get("detector_repo_commit"), P24D_COMMIT, f"{label} detector commit")
    _require(remediation.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(remediation.get("to_rules_tree_sha256"), P24D_HASH, f"{label} to hash")
    _require(remediation.get("rule_file"), "rules/example_safe.yml", f"{label} rule file")
    _require(remediation.get("rule_file_git_blob_sha1"), P24D_RULE_BLOB, f"{label} rule blob")
    _require(
        legacy._git_blob_sha1(repo / "rules/example_safe.yml"),
        P24D_RULE_BLOB,
        f"{label} live rule blob",
    )
    _require(
        remediation.get("changed_rules"),
        ["R-PS-Bypass", "R-SCREENSHOT-Capture", "R-LSASS-Dump"],
        f"{label} changed rules",
    )
    _require(remediation.get("fresh_attack_revalidation"), "NOT_RUN", f"{label} fresh attack")
    _require(remediation.get("fresh_benign_revalidation"), "NOT_RUN", f"{label} fresh benign")

    expected_patterns = {
        "R-PS-Bypass": "-windowstyle hidden|-executionpolicy bypass",
        "R-SCREENSHOT-Capture": "copyfromscreen|graphics.copyfromscreen|bitblt",
        "R-LSASS-Dump": "comsvcs.dll, MiniDump|sekurlsa::logonpasswords|procdump -ma lsass",
    }
    for rule_id, pattern in expected_patterns.items():
        live = legacy._load_rule(repo, "rules/example_safe.yml", rule_id)
        _require(live.get("field"), "command_line", f"{label} {rule_id} field")
        _require(live.get("operator"), "contains", f"{label} {rule_id} operator")
        _require(live.get("pattern"), pattern, f"{label} {rule_id} pattern")

    parent = _mapping(record.get("canonical_p2_24c"), f"{label} parent")
    _require(parent.get("parsed_events"), 34534, f"{label} parent parsed events")
    _require(parent.get("flagged_events"), 2404, f"{label} parent flagged events")
    _require(parent.get("findings"), 2404, f"{label} parent findings")

    diagnostic = _mapping(record.get("diagnostic_method"), f"{label} diagnostic")
    _require(diagnostic.get("detector_rerun"), False, f"{label} detector rerun")
    _require(diagnostic.get("canonical_result_modified"), False, f"{label} canonical modified")
    _require(diagnostic.get("raw_events_seen"), 34534, f"{label} raw events")
    _require(
        diagnostic.get("canonical_rule_counts_reproduced_by_raw_predicates"),
        True,
        f"{label} predicate reproduction",
    )

    posthoc = _mapping(
        record.get("posthoc_counterfactual_after_three_narrow_changes"),
        f"{label} counterfactual",
    )
    _require(posthoc.get("estimated_flagged_events"), 570, f"{label} estimated flagged")
    _require(
        posthoc.get("estimated_flagged_event_percent"),
        1.6505472867319164,
        f"{label} estimated percent",
    )
    _require(
        posthoc.get("estimated_reduction_from_p2_24c_flagged_events"),
        1834,
        f"{label} estimated reduction",
    )

    claims = _mapping(record.get("claim_boundary"), f"{label} claims")
    _require(claims.get("p2_24c_is_now_development_data"), True, f"{label} dev data")
    _require(claims.get("counterfactual_is_fresh_measurement"), False, f"{label} fresh")
    _require(claims.get("counterfactual_is_independent_validation"), False, f"{label} independent")
    _require(claims.get("confirmed_false_positives"), "NOT_CLAIMED", f"{label} confirmed FP")
    _require(
        claims.get("general_fresh_full_benign_fpr_for_current_rulepack"),
        "NOT_CLAIMED",
        f"{label} benign FPR",
    )
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} production FPR")

    return P24D_HASH, {
        "remediation_id": P24D_ID,
        "detector_repo_commit": P24D_COMMIT,
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": P24D_HASH,
        "change_class": "posthoc_benign_noise_narrowing",
        "p2_24c_development_data": True,
        "estimated_flagged_events_on_p2_24c_development_data": 570,
        "estimated_flagged_event_percent_on_p2_24c_development_data": 1.6505472867319164,
        "fresh_attack_revalidation": "NOT_RUN",
        "fresh_benign_revalidation": "NOT_RUN",
        "production_false_positive_rate": "NOT_CLAIMED",
    }



def _verify_p2_25(repo: Path, row: Mapping[str, Any]) -> dict[str, Any]:
    label = "P2-25"
    _require(row.get("revalidation_id"), P25_ID, f"{label} chain id")
    _require(row.get("class"), "fresh_external_attack_fixture_revalidation", f"{label} class")
    _require(row.get("detector_rules_tree_sha256"), P25_RULE_HASH, f"{label} detector hash")
    for key, expected in {"fixture_count": 8, "hits": 6, "misses": 2, "errors": 0}.items():
        _require(row.get(key), expected, f"{label} chain {key}")
    _require(row.get("fixture_hit_rate"), 0.75, f"{label} chain hit rate")
    _require(row.get("event_level_ground_truth"), "NOT_AVAILABLE", f"{label} event ground truth")
    _require(row.get("fixture_hit_rate_is_event_level_recall"), False, f"{label} recall boundary")
    _require(row.get("fresh_attack_revalidation"), "COMPLETED", f"{label} completion")

    result_path = legacy._relative_file(repo, row.get("result_record"), f"{label} result")
    record = legacy._load_yaml(result_path)
    _require(record.get("schema"), "breachscope.p2_25_deepblue_attack_result.v1", f"{label} result schema")
    _require(record.get("analysis_class"), "fresh_external_attack_fixture_revalidation", f"{label} result class")
    _require(record.get("status"), "COMPLETED", f"{label} result status")

    artifacts = _mapping(record.get("artifacts"), f"{label} artifacts")
    measurement = _mapping(artifacts.get("measurement"), f"{label} measurement artifact")
    _require(measurement.get("stored_sha256"), P25_RESULT_SHA, f"{label} stored result SHA")
    raw = _locked_json(repo, measurement.get("path"), P25_RESULT_SHA, f"{label} raw result")
    _require(raw.get("status"), "completed", f"{label} raw status")
    frozen = _mapping(raw.get("frozen_product"), f"{label} frozen product")
    _require(frozen.get("rules_tree_sha256"), P25_RULE_HASH, f"{label} raw rule hash")
    _require(frozen.get("rule_count"), 68, f"{label} raw rule count")

    summary = _mapping(raw.get("summary"), f"{label} summary")
    for key, expected in {"fixture_count": 8, "hits": 6, "misses": 2, "errors": 0}.items():
        _require(summary.get(key), expected, f"{label} summary {key}")
    _require(summary.get("fixture_hit_rate"), 0.75, f"{label} summary rate")

    datasets = raw.get("datasets")
    if not isinstance(datasets, list) or len(datasets) != 8:
        raise CurrentEvidenceError(f"{label} must contain exactly eight fixture results")
    statuses = {item.get("dataset_id"): item.get("fixture_status") for item in datasets}
    _require(statuses, {
        "obfuscation-encoding": "MISS",
        "metasploit-psexec-powershell-security": "HIT",
        "mimikatz-lsadump-sam": "HIT",
        "password-spray": "HIT",
        "powersploit-security": "HIT",
        "psattack-security": "HIT",
        "new-user-security": "MISS",
        "eventlog-manipulation": "HIT",
    }, f"{label} fixture statuses")
    _require(sum(int(item.get("parsed_events", 0)) for item in datasets), 450, f"{label} parsed events")
    _require(sum(int(item.get("parse_errors", 0)) for item in datasets), 0, f"{label} parse errors")

    boundary = _mapping(record.get("evidence_boundary"), f"{label} boundary")
    _require(boundary.get("fresh_attack_revalidation_completed"), True, f"{label} completed")
    _require(boundary.get("fixture_hit_rate_is_event_level_recall"), False, f"{label} event recall")
    _require(boundary.get("event_level_recall"), "NOT_CLAIMED", f"{label} event recall claim")
    _require(boundary.get("technique_recall"), "NOT_CLAIMED", f"{label} technique recall")
    _require(boundary.get("production_recall"), "NOT_CLAIMED", f"{label} production recall")

    return {
        "revalidation_id": P25_ID,
        "detector_rules_tree_sha256": P25_RULE_HASH,
        "fixture_count": 8,
        "hits": 6,
        "misses": 2,
        "errors": 0,
        "fixture_hit_rate": 0.75,
        "fixture_hit_rate_is_event_level_recall": False,
        "event_level_recall": "NOT_CLAIMED",
        "production_recall": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    chain = legacy._load_yaml(chain_path)
    _require(chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    _require(
        chain.get("current_evidence_id"),
        "p2-25-fresh-attack-revalidation-current-detection-evidence",
        "current evidence id",
    )
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
        P20_ID,
    ]
    _require([row.get("calibration_id") for row in calibrations], expected_ids, "calibration chain order/content")

    history = _verify_history_through_h(repo, chain)
    j_path = legacy._relative_file(repo, calibrations[5].get("measurement_record"), "P2-11J measurement")
    j_record = legacy._load_yaml(j_path)
    j_hash, j = _verify_j(repo, j_record, H_HASH)

    p20_path = legacy._relative_file(
        repo,
        calibrations[6].get("measurement_record"),
        "P2-20 measurement",
    )
    p20_record = legacy._load_yaml(p20_path)
    p20_hash, p20 = _verify_p2_20(repo, p20_record, j_hash)

    posthoc_rows = chain.get("posthoc_remediations")
    if not isinstance(posthoc_rows, list) or len(posthoc_rows) != 1:
        raise CurrentEvidenceError("posthoc_remediations must contain exactly P2-24D")
    posthoc_row = _mapping(posthoc_rows[0], "P2-24D chain row")
    _require(posthoc_row.get("remediation_id"), P24D_ID, "P2-24D chain id")
    _require(
        posthoc_row.get("from_rules_tree_sha256"),
        p20_hash,
        "P2-24D chain from hash",
    )
    _require(
        posthoc_row.get("to_rules_tree_sha256"),
        P24D_HASH,
        "P2-24D chain to hash",
    )
    _require(posthoc_row.get("fresh_attack_revalidation"), "NOT_RUN", "P2-24D chain attack")
    _require(posthoc_row.get("fresh_benign_revalidation"), "NOT_RUN", "P2-24D chain benign")

    p24d_path = legacy._relative_file(
        repo,
        posthoc_row.get("diagnosis_record"),
        "P2-24D diagnosis",
    )
    p24d_record = legacy._load_yaml(p24d_path)
    final_hash, p24d = _verify_p2_24d(repo, p24d_record, p20_hash)

    revalidation_rows = chain.get("post_remediation_revalidations")
    if not isinstance(revalidation_rows, list) or len(revalidation_rows) != 1:
        raise CurrentEvidenceError("post_remediation_revalidations must contain exactly P2-25")
    p25_row = _mapping(revalidation_rows[0], "P2-25 chain row")
    p25 = _verify_p2_25(repo, p25_row)

    current_hash, rule_file_count = legacy.historical._rules_tree_hash(repo / "rules")
    _require(final_hash, current_hash, "current rule tree explained by chain")
    detector = _mapping(chain.get("current_frozen_detector"), "current frozen detector")
    _require(detector.get("repo_commit"), P24D_COMMIT, "current detector commit")
    _require(detector.get("rules_tree_sha256"), P24D_HASH, "current detector rule hash")
    _require(detector.get("rule_count"), 68, "current detector rule count")
    _require(detector.get("rule_file_count"), 5, "current detector rule file count")

    claims = _mapping(chain.get("claim_boundary"), "current evidence claims")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", "production accuracy")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", "production FPR")
    _require(claims.get("final_blind_holdout"), False, "final blind holdout")
    _require(claims.get("fresh_full_benign_fpr_for_current_rulepack"), "NOT_CLAIMED", "fresh full benign FPR")

    return {
        "schema": "breachscope.current_detection_evidence_verification.v8",
        "current_evidence_id": chain.get("current_evidence_id"),
        "status": "PASS",
        "base_rules_tree_sha256": history["base_rules_tree_sha256"],
        "current_rules_tree_sha256": current_hash,
        "rule_file_count": rule_file_count,
        "base_attack_scenario_hits": history["base_attack_scenario_hits"],
        "current_attack_scenario_hits": history["current_attack_scenario_hits"],
        "current_attack_scenario_hits_applies_to_current_rulepack": False,
        "attack_scenario_total": history["attack_scenario_total"],
        "fresh_attack_revalidation_after_current_rule_change": "COMPLETED",
        "fresh_attack_fixture_hits": p25["hits"],
        "fresh_attack_fixture_total": p25["fixture_count"],
        "fresh_attack_fixture_hit_rate": p25["fixture_hit_rate"],
        "fresh_benign_revalidation_after_current_rule_change": "NOT_RUN",
        "historical_benign": history["historical_benign"],
        "remediations": history["remediations"],
        "calibrations": [*history["calibrations"], j, p20],
        "posthoc_remediations": [p24d],
        "post_remediation_revalidations": [p25],
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
            if "scenario_hits_before" in calibration:
                print(
                    f"{calibration['calibration_id']}: "
                    f"{calibration['scenario_hits_before']}/{calibration['scenario_total']} -> "
                    f"{calibration['scenario_hits_after']}/{calibration['scenario_total']}"
                )
            else:
                print(
                    f"{calibration['calibration_id']}: "
                    f"{calibration['dataset_hits_before']}/{calibration['dataset_total']} -> "
                    f"{calibration['dataset_hits_after']}/{calibration['dataset_total']} post-hoc"
                )
        print(f"Fresh attack revalidation after current rule change: {result['fresh_attack_fixture_hits']}/{result['fresh_attack_fixture_total']} fixtures")
        print("Fresh full benign FPR for current rulepack: NOT CLAIMED")
        print("Production accuracy/FPR: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
