#!/usr/bin/env python3
"""Verify the current detection-evidence chain through P2-35M revalidation."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
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

P26C_ID = "p2-26c-gha-windows-fresh-benign"
P26C_RESULT_SHA = "9cff2b8616632031807dffa4771eb69e37f1040ef28576b9bd73442bbeb3264c"
P26C_LOCK_SHA = "cde7cb5ca7d6e5225592a9354694daa59d6deb536d825f3c662a62427b732906"
P26C_RULE_HASH = P24D_HASH
P26C_CURRENT_ID = "p2-26c-fresh-benign-revalidation-current-detection-evidence"

P29_ID = "p2-29-single-parse-evtx"
P29_RECORD = "external_baseline/p2_29_single_parse_parser_maintenance.yaml"
P29_RECORD_SHA = "3958351d3465d9ab2667696c0c02165765d1e3b24a14ea1695c5f22405cc2905"
P29_INGEST_BLOB = "34534bf8256ce658c5f05991c05045f7c5066816"

P35I_ID = "p2-35i-original-filename-masquerading-remediation"
P35I_HASH = "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
P35I_COMMIT = "d53861ea1dca4a5cf2ed57e7d147ab04b244e7f4"
P35I_RULE_BLOB = "8d379322ef74a88ebd6ef089e0b0c5386fad7cae"
P35I_CANONICAL_BLOB = "547e4ecf6d76166c9766fb2c5e4ab3571f94416c"
P35I_COMPARE_BLOB = "969c9a3649a13e3f7e939761203f706dbe61fc6a"
P35I_RECORD = "external_baseline/p2_35i_masquerading_remediation.yaml"
P35I_CONTRACT = "external_baseline/p2_35i_masquerading_candidate_contract.yaml"
P35I_CONTRACT_SHA = "10311ea854baf4c5576e628935a55d0051ee6c643d51e9166004b5c34704c6a9"
P35I_CURRENT_ID = "p2-35i-masquerading-current-detection-evidence"

P35M_ID = "p2-35m-current-rulepack-fresh-source-revalidation"
P35M_ANALYSIS_ID = "p2-35m-current-rulepack-fresh-source-revalidation-v1"
P35M_CURRENT_ID = "p2-35m-current-rulepack-fresh-source-revalidation-current-detection-evidence"
P35M_RESULT_RECORD = "external_baseline/p2_35m_current_rulepack_fresh_source_revalidation_result.yaml"
P35M_RAW = "external_baseline/results/p2_35m_4aa6a1d/result.json"
P35M_LOCK = "external_baseline/locks/P2_35M_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
P35M_RAW_SHA = "14a3143f5b674c97685910ff1040ba92f3bd7bd80e262598adeb71f59bcce9e0"
P35M_LOCK_SHA = "e374b17549707b97173c42aa852abb51e611d2c5d1c774a7e54ecbcc0c2a0f0f"
P35M_CONTRACT_SHA = "0636d07c4ab3ea15b790c7f872d86aadcc999810db2cfaea78e9ddff44824b2a"
P35M_RUNNER_SHA = "c50c2b7abb06ff9e8406443767a0ff7701b3a76c4abf7187cd4d487dae2b9427"
P35M_PRODUCT_COMMIT = "2401f8b9b6a569b8b932451f0a0ae20ffa26abbc"

CMDGAP_ID = "independent-command-coverage-remediation-v1"
CMDGAP_HASH = "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
CMDGAP_COMMIT = "bad0c88037d489f5b375c120002be74ac6082ffa"
CMDGAP_RECORD = "external_baseline/independent_command_coverage_remediation.yaml"
CMDGAP_CURRENT_ID = "independent-command-coverage-remediation-current-detection-evidence"
CMDGAP_EXAMPLE_BLOB = "554f7bf200b31f85bb6fa3df9ff4651d8fe0eb6c"
CMDGAP_P20_BLOB = "787a510c233d7ccedc38bd88a2de2f7cbb34ac6b"



def _require(actual: Any, expected: Any, label: str) -> None:
    previous._require(actual, expected, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    return previous._mapping(value, label)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_blob_at_commit(repo: Path, commit: str, relative_path: str) -> str:
    try:
        value = subprocess.check_output(
            ["git", "rev-parse", f"{commit}:{relative_path}"],
            cwd=repo,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise CurrentEvidenceError(
            f"cannot resolve historical blob {commit}:{relative_path}: {exc.output.strip()}"
        ) from exc
    if len(value) != 40:
        raise CurrentEvidenceError(
            f"invalid historical blob id for {commit}:{relative_path}: {value!r}"
        )
    return value


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
        _git_blob_at_commit(repo, P20_COMMIT, "rules/p2_20_postholdout_rules.yml"),
        P20_RULE_BLOB,
        f"{label} historical rule blob",
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
    _require(parser.get("helper"), "iter_event_xml_records", f"{label} parser helper")

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
        _git_blob_at_commit(repo, P24D_COMMIT, "rules/example_safe.yml"),
        P24D_RULE_BLOB,
        f"{label} historical rule blob",
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



def _verify_p2_26c(repo: Path, row: Mapping[str, Any]) -> dict[str, Any]:
    label = "P2-26C"
    _require(row.get("revalidation_id"), P26C_ID, f"{label} chain id")
    _require(
        row.get("class"),
        "fresh_external_ephemeral_ci_benign_revalidation",
        f"{label} class",
    )
    _require(row.get("detector_rules_tree_sha256"), P26C_RULE_HASH, f"{label} detector hash")
    for key, expected in {
        "parsed_events": 1643,
        "parse_errors": 0,
        "findings": 1,
        "flagged_events": 1,
    }.items():
        _require(row.get(key), expected, f"{label} chain {key}")
    _require(
        row.get("observed_source_intent_benign_flagged_event_fraction"),
        0.0006086427267194157,
        f"{label} chain fraction",
    )
    _require(
        row.get("observed_source_intent_benign_flagged_event_percent"),
        0.06086427267194157,
        f"{label} chain percent",
    )
    _require(row.get("event_level_ground_truth"), "NOT_AVAILABLE", f"{label} ground truth")
    _require(
        row.get("flagged_events_are_confirmed_false_positives"),
        False,
        f"{label} confirmed FP boundary",
    )
    _require(row.get("fresh_benign_revalidation"), "COMPLETED", f"{label} completion")
    _require(
        row.get("production_false_positive_rate"),
        "NOT_CLAIMED",
        f"{label} production FPR",
    )

    result_path = legacy._relative_file(repo, row.get("result_record"), f"{label} result")
    record = legacy._load_yaml(result_path)
    _require(
        record.get("schema"),
        "breachscope.p2_26c_gha_windows_benign_result.v1",
        f"{label} result schema",
    )
    _require(
        record.get("analysis_class"),
        "fresh_external_ephemeral_ci_benign_revalidation",
        f"{label} result class",
    )
    _require(record.get("status"), "COMPLETED", f"{label} result status")

    artifacts = _mapping(record.get("artifacts"), f"{label} artifacts")
    measurement_artifact = _mapping(
        artifacts.get("measurement"),
        f"{label} measurement artifact",
    )
    _require(
        measurement_artifact.get("stored_sha256"),
        P26C_RESULT_SHA,
        f"{label} stored result SHA",
    )
    raw = _locked_json(
        repo,
        measurement_artifact.get("path"),
        P26C_RESULT_SHA,
        f"{label} raw result",
    )
    lock_artifact = _mapping(artifacts.get("permanent_lock"), f"{label} lock artifact")
    _require(lock_artifact.get("stored_sha256"), P26C_LOCK_SHA, f"{label} lock SHA record")
    lock_path = legacy._relative_file(repo, lock_artifact.get("path"), f"{label} lock")
    _require(_sha256(lock_path), P26C_LOCK_SHA, f"{label} lock SHA")

    _require(raw.get("status"), "completed", f"{label} raw status")
    frozen = _mapping(raw.get("frozen_product"), f"{label} frozen product")
    _require(frozen.get("rules_tree_sha256"), P26C_RULE_HASH, f"{label} raw rule hash")
    _require(frozen.get("rule_count"), 68, f"{label} raw rule count")
    _require(frozen.get("rule_file_count"), 5, f"{label} raw rule files")

    parse_summary = _mapping(raw.get("parse_summary"), f"{label} parse summary")
    _require(parse_summary.get("raw_records"), 1643, f"{label} raw records")
    _require(parse_summary.get("parsed_events"), 1643, f"{label} parsed events")
    _require(parse_summary.get("parse_errors"), 0, f"{label} parse errors")

    measurement = _mapping(raw.get("measurement"), f"{label} measurement")
    _require(measurement.get("status"), "MEASURED", f"{label} measurement status")
    _require(measurement.get("parsed_events"), 1643, f"{label} measured events")
    _require(measurement.get("parse_errors"), 0, f"{label} measured parse errors")
    _require(measurement.get("flagged_events"), 1, f"{label} flagged events")
    _require(measurement.get("findings"), 1, f"{label} findings")
    _require(measurement.get("rules_evaluated"), 68, f"{label} rules")
    _require(
        measurement.get("observed_source_intent_benign_flagged_event_fraction"),
        0.0006086427267194157,
        f"{label} fraction",
    )
    _require(
        measurement.get("observed_source_intent_benign_flagged_event_percent"),
        0.06086427267194157,
        f"{label} percent",
    )
    _require(measurement.get("findings_by_rule"), {"R-SCHTASK-4698": 1}, f"{label} rules")
    _require(measurement.get("findings_by_channel"), {"Security": 1}, f"{label} channels")
    _require(
        measurement.get("flagged_events_by_channel"),
        {"Security": 1},
        f"{label} flagged channels",
    )

    channels = raw.get("channels")
    if not isinstance(channels, list) or len(channels) != 5:
        raise CurrentEvidenceError(f"{label} must contain exactly five channel rows")
    expected_channels = {
        "Security": (1212, 1212, 0),
        "System": (347, 347, 0),
        "Application": (84, 84, 0),
        "Windows PowerShell": (0, 0, 0),
        "Microsoft-Windows-PowerShell/Operational": (0, 0, 0),
    }
    observed_channels = {
        item.get("channel"): (
            item.get("raw_records"),
            item.get("parsed_events"),
            item.get("parse_errors"),
        )
        for item in channels
    }
    _require(observed_channels, expected_channels, f"{label} channel counts")

    raw_boundary = _mapping(raw.get("claim_boundary"), f"{label} raw boundary")
    _require(
        raw_boundary.get("event_level_benign_ground_truth"),
        "NOT_AVAILABLE",
        f"{label} event ground truth",
    )
    _require(
        raw_boundary.get("confirmed_false_positive_rate"),
        "NOT_CLAIMED",
        f"{label} confirmed FPR",
    )
    _require(
        raw_boundary.get("production_false_positive_rate"),
        "NOT_CLAIMED",
        f"{label} production FPR",
    )
    _require(
        raw_boundary.get("measured_value_is_production_fpr"),
        False,
        f"{label} production boundary",
    )

    evidence_boundary = _mapping(record.get("evidence_boundary"), f"{label} boundary")
    _require(
        evidence_boundary.get("fresh_benign_revalidation_completed"),
        True,
        f"{label} completed",
    )
    _require(
        evidence_boundary.get("flagged_events_are_confirmed_false_positives"),
        False,
        f"{label} confirmed FP",
    )
    _require(
        evidence_boundary.get("production_false_positive_rate"),
        "NOT_CLAIMED",
        f"{label} production claim",
    )

    execution = _mapping(record.get("execution"), f"{label} execution")
    _require(
        execution.get("contract_merge_commit"),
        "81b839d84f07a724fd010c98c5bb44f8c40a2fd6",
        f"{label} contract merge",
    )
    _require(execution.get("one_pass"), True, f"{label} one pass")
    _require(execution.get("rerun_allowed"), False, f"{label} rerun")
    _require(
        execution.get("first_completed_or_failed_execution_is_canonical"),
        True,
        f"{label} canonical",
    )

    return {
        "revalidation_id": P26C_ID,
        "detector_rules_tree_sha256": P26C_RULE_HASH,
        "parsed_events": 1643,
        "parse_errors": 0,
        "findings": 1,
        "flagged_events": 1,
        "observed_source_intent_benign_flagged_event_fraction": 0.0006086427267194157,
        "observed_source_intent_benign_flagged_event_percent": 0.06086427267194157,
        "flagged_events_are_confirmed_false_positives": False,
        "production_false_positive_rate": "NOT_CLAIMED",
    }



def _verify_p2_29_parser_maintenance(
    repo: Path,
    chain: Mapping[str, Any],
) -> dict[str, Any]:
    rows = chain.get("parser_maintenance")
    if not isinstance(rows, list) or len(rows) != 1:
        raise CurrentEvidenceError(
            "parser_maintenance must contain exactly P2-29"
        )

    row = _mapping(rows[0], "P2-29 parser maintenance chain row")
    _require(row.get("maintenance_id"), P29_ID, "P2-29 chain id")
    _require(row.get("record"), P29_RECORD, "P2-29 chain record")
    _require(
        row.get("change_class"),
        "semantics_preserving_parser_performance_refactor",
        "P2-29 chain change class",
    )
    _require(row.get("from_git_blob_sha1"), P20_INGEST_BLOB, "P2-29 from blob")
    _require(row.get("to_git_blob_sha1"), P29_INGEST_BLOB, "P2-29 to blob")
    _require(row.get("current_evidence_id_changed"), False, "P2-29 evidence id")
    _require(row.get("rules_tree_changed"), False, "P2-29 rule tree")
    _require(
        row.get("normalized_event_semantics"),
        "PRESERVED_BY_EQUIVALENCE_CHECKS",
        "P2-29 semantics",
    )

    path = legacy._relative_file(repo, P29_RECORD, "P2-29 maintenance record")
    _require(_sha256(path), P29_RECORD_SHA, "P2-29 maintenance record SHA")
    record = legacy._load_yaml(path)
    _require(
        record.get("schema"),
        "breachscope.p2_29_parser_maintenance.v1",
        "P2-29 schema",
    )
    _require(record.get("maintenance_id"), P29_ID, "P2-29 record id")
    _require(
        record.get("change_class"),
        "semantics_preserving_parser_performance_refactor",
        "P2-29 record change class",
    )

    parser = _mapping(record.get("parser"), "P2-29 parser")
    _require(parser.get("file"), "breachscope/ingest.py", "P2-29 parser file")
    _require(
        parser.get("historical_p2_20_git_blob_sha1"),
        P20_INGEST_BLOB,
        "P2-29 historical parser blob",
    )
    _require(
        parser.get("current_git_blob_sha1"),
        P29_INGEST_BLOB,
        "P2-29 recorded live parser blob",
    )
    _require(
        legacy._git_blob_sha1(repo / "breachscope/ingest.py"),
        P29_INGEST_BLOB,
        "P2-29 live parser blob",
    )
    _require(
        parser.get("canonical_elementtree_fromstring_calls_per_valid_record"),
        1,
        "P2-29 parse count",
    )
    _require(
        parser.get("public_convert_evtx_dir_signature_changed"),
        False,
        "P2-29 convert signature",
    )

    equivalence = _mapping(record.get("equivalence"), "P2-29 equivalence")

    p25_compat = _mapping(equivalence.get("p2_25"), "P2-29 P2-25 equivalence")
    for key, expected in {
        "exact_evtx_files": 8,
        "records_compared": 450,
        "old_parse_errors": 0,
        "new_parse_errors": 0,
        "mismatches": 0,
    }.items():
        _require(p25_compat.get(key), expected, f"P2-29 P2-25 {key}")
    _require(
        p25_compat.get("all_normalized_dicts_equal"),
        True,
        "P2-29 P2-25 equality",
    )
    for key in ("old_aggregate_digest_sha256", "new_aggregate_digest_sha256"):
        _require(
            p25_compat.get(key),
            "dad2930a569b11f0256d890ba6427bb09a5925cc89f82eaab95691cccaf0a303",
            f"P2-29 P2-25 {key}",
        )

    p26c_compat = _mapping(equivalence.get("p2_26c"), "P2-29 P2-26C equivalence")
    for key, expected in {
        "exact_evtx_files": 5,
        "records_compared": 1643,
        "old_parse_errors": 0,
        "new_parse_errors": 0,
        "mismatches": 0,
    }.items():
        _require(p26c_compat.get(key), expected, f"P2-29 P2-26C {key}")
    _require(
        p26c_compat.get("all_normalized_dicts_equal"),
        True,
        "P2-29 P2-26C equality",
    )
    for key in ("old_aggregate_digest_sha256", "new_aggregate_digest_sha256"):
        _require(
            p26c_compat.get(key),
            "29fbe83203c47206ee86e66798f287c8a9b02cc3973731ac6dec389a82ee78a3",
            f"P2-29 P2-26C {key}",
        )

    combined = _mapping(
        equivalence.get("combined_current_revalidation_sources"),
        "P2-29 combined equivalence",
    )
    for key, expected in {
        "exact_evtx_files": 13,
        "records_compared": 2093,
        "old_parse_errors": 0,
        "new_parse_errors": 0,
        "mismatches": 0,
    }.items():
        _require(combined.get(key), expected, f"P2-29 combined {key}")
    _require(
        combined.get("all_normalized_dicts_equal"),
        True,
        "P2-29 combined equality",
    )
    for key in ("old_aggregate_digest_sha256", "new_aggregate_digest_sha256"):
        _require(
            combined.get(key),
            "a22fb6b0cb9faed59ab2813629e6dea7625ccad7519c512d0b99e9587d7ec8d9",
            f"P2-29 combined {key}",
        )

    development = _mapping(
        record.get("development_only_probe"),
        "P2-29 development-only probe",
    )
    _require(development.get("records_compared"), 2000, "P2-29 development records")
    _require(development.get("mismatches"), 0, "P2-29 development mismatches")
    _require(
        development.get("all_normalized_dicts_equal"),
        True,
        "P2-29 development equality",
    )
    _require(
        development.get("formal_performance_result"),
        False,
        "P2-29 development formal result",
    )
    _require(
        development.get("use_for_speedup_claim"),
        False,
        "P2-29 development speed claim",
    )

    preservation = _mapping(record.get("preservation"), "P2-29 preservation")
    _require(
        preservation.get("current_evidence_id"),
        P26C_CURRENT_ID,
        "P2-29 current evidence id",
    )
    _require(
        preservation.get("rules_tree_sha256"),
        P24D_HASH,
        "P2-29 current rule hash",
    )
    _require(
        preservation.get("p2_20_measurement_modified"),
        False,
        "P2-29 P2-20 preservation",
    )
    _require(
        preservation.get("p2_25_canonical_result_modified"),
        False,
        "P2-29 P2-25 preservation",
    )
    _require(
        preservation.get("p2_26c_canonical_result_modified"),
        False,
        "P2-29 P2-26C preservation",
    )
    _require(
        preservation.get("detection_rerun_for_replacement_score"),
        False,
        "P2-29 detection rerun",
    )

    claim = _mapping(record.get("claim_boundary"), "P2-29 claim boundary")
    _require(claim.get("speedup"), "NOT_YET_FORMALLY_MEASURED", "P2-29 speed")
    _require(claim.get("production_capacity"), "NOT_CLAIMED", "P2-29 capacity")
    _require(
        claim.get("normalized_event_semantics"),
        "PRESERVED_ON_EXACT_CURRENT_REVALIDATION_SOURCES",
        "P2-29 normalized semantics",
    )
    _require(
        claim.get("detection_accuracy_changed"),
        False,
        "P2-29 detection accuracy",
    )

    source = (repo / "breachscope/ingest.py").read_text(encoding="utf-8")
    for marker in (
        "def _extract_legacy_event_fields_from_root(",
        "def _bs_extract_evtx_raw_from_root(",
        "def _extract_with_raw_evidence(",
        "def iter_event_xml_records(",
    ):
        _require(marker in source, True, f"P2-29 source marker {marker}")

    return {
        "maintenance_id": P29_ID,
        "change_class": "semantics_preserving_parser_performance_refactor",
        "historical_p2_20_parser_blob": P20_INGEST_BLOB,
        "current_parser_blob": P29_INGEST_BLOB,
        "p2_25_records_compared": 450,
        "p2_26c_records_compared": 1643,
        "total_current_revalidation_records_compared": 2093,
        "total_mismatches": 0,
        "combined_normalized_digest_sha256": "a22fb6b0cb9faed59ab2813629e6dea7625ccad7519c512d0b99e9587d7ec8d9",
        "current_evidence_id_changed": False,
        "rules_tree_changed": False,
        "speedup": "NOT_YET_FORMALLY_MEASURED",
    }


def _verify_p2_35i(
    repo: Path,
    record: Mapping[str, Any],
    previous_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "P2-35I"
    _require(record.get("schema"), "breachscope.p2_35i_masquerading_remediation.v1", f"{label} schema")
    _require(record.get("analysis_id"), "p2-35i-original-filename-masquerading-remediation", f"{label} id")
    _require(record.get("status"), "IMPLEMENTED_POSTHOC_PENDING_FRESH_REVALIDATION", f"{label} status")
    _require(record.get("analysis_class"), "POSTHOC_DEVELOPMENT_REMEDIATION_NOT_FRESH_VALIDATION", f"{label} class")

    contract = _mapping(record.get("contract"), f"{label} contract")
    _require(contract.get("path"), P35I_CONTRACT, f"{label} contract path")
    _require(contract.get("merge_commit"), "d7cfe656bd2fce2518a1a1435ffd6878e4b3e248", f"{label} contract merge")
    _require(contract.get("sha256"), P35I_CONTRACT_SHA, f"{label} contract SHA")
    contract_path = legacy._relative_file(repo, P35I_CONTRACT, f"{label} contract file")
    _require(_sha256(contract_path), P35I_CONTRACT_SHA, f"{label} live contract SHA")

    remediation = _mapping(record.get("remediation"), f"{label} remediation")
    _require(remediation.get("remediation_id"), P35I_ID, f"{label} remediation id")
    _require(remediation.get("change_class"), "posthoc_attack_gap_remediation", f"{label} change class")
    _require(remediation.get("detector_repo_commit"), P35I_COMMIT, f"{label} detector commit")
    _require(remediation.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(remediation.get("to_rules_tree_sha256"), P35I_HASH, f"{label} to hash")
    _require(remediation.get("rule_count_before"), 68, f"{label} rule count before")
    _require(remediation.get("rule_count_after"), 69, f"{label} rule count after")
    _require(remediation.get("rule_file_count"), 5, f"{label} rule file count")
    _require(remediation.get("rule_file"), "rules/p2_10_event_rules.yml", f"{label} rule file")
    _require(remediation.get("rule_file_git_blob_sha1"), P35I_RULE_BLOB, f"{label} rule blob")
    _require(remediation.get("canonical_file"), "breachscope/canonical.py", f"{label} canonical file")
    _require(remediation.get("canonical_file_git_blob_sha1"), P35I_CANONICAL_BLOB, f"{label} canonical blob")
    _require(remediation.get("field_compare_file"), "breachscope/rule_field_compare.py", f"{label} compare file")
    _require(remediation.get("field_compare_file_git_blob_sha1"), P35I_COMPARE_BLOB, f"{label} compare blob")
    _require(remediation.get("added_rule_id"), "R-MASQUERADE-ORIGINAL-NAME-MISMATCH", f"{label} added rule")
    _require(remediation.get("fresh_attack_revalidation"), "NOT_RUN", f"{label} fresh attack")
    _require(remediation.get("fresh_benign_revalidation"), "NOT_RUN", f"{label} fresh benign")

    _require(legacy._git_blob_sha1(repo / "rules/p2_10_event_rules.yml"), P35I_RULE_BLOB, f"{label} live rule blob")
    _require(legacy._git_blob_sha1(repo / "breachscope/canonical.py"), P35I_CANONICAL_BLOB, f"{label} live canonical blob")
    _require(legacy._git_blob_sha1(repo / "breachscope/rule_field_compare.py"), P35I_COMPARE_BLOB, f"{label} live compare blob")

    live_rule = legacy._load_rule(repo, "rules/p2_10_event_rules.yml", "R-MASQUERADE-ORIGINAL-NAME-MISMATCH")
    _require(live_rule.get("field"), "canonical.process.executable", f"{label} rule field")
    _require(live_rule.get("operator"), "regex", f"{label} rule operator")
    _require(
        live_rule.get("pattern"),
        r"(?i)^(?:[a-z]:\\[^\\]+\.exe|[a-z]:\\windows\\[^\\]+\.exe|[a-z]:\\windows\\temp\\.+\.exe|[a-z]:\\users\\[^\\]+\\appdata\\(?:roaming|local\\temp)\\.+\.exe)$",
        f"{label} rule pattern",
    )
    _require(live_rule.get("severity"), "medium", f"{label} severity")
    _require(live_rule.get("mitre_technique"), "T1036.003", f"{label} technique")
    _require(
        live_rule.get("all_of"),
        [
            {"field": "canonical.process.executable", "operator": "basename_not_equals_field", "pattern": "OriginalFileName"},
            {"field": "canonical.process.parent_executable", "operator": "regex", "pattern": r"(?i)^c:\\windows\\system32\\(?:cmd\.exe|windowspowershell\\v1\.0\\powershell\.exe)$"},
            {"field": "event_id", "operator": "equals", "pattern": "1"},
            {"field": "source", "operator": "equals", "pattern": "Microsoft-Windows-Sysmon"},
        ],
        f"{label} all_of",
    )

    implementation = _mapping(record.get("implementation"), f"{label} implementation")
    ecs = _mapping(implementation.get("ecs_process_fallback"), f"{label} ECS fallback")
    _require(ecs.get("executable_source"), "raw.process.executable", f"{label} ECS executable")
    _require(ecs.get("parent_executable_source"), "raw.process.parent.executable", f"{label} ECS parent")
    _require(ecs.get("legacy_image_fields_take_precedence"), True, f"{label} legacy precedence")
    compare = _mapping(implementation.get("basename_field_compare"), f"{label} basename compare")
    _require(compare.get("operator"), "basename_not_equals_field", f"{label} compare operator")
    _require(compare.get("scope"), "ALL_OF_ONLY", f"{label} compare scope")
    _require(compare.get("case_insensitive"), True, f"{label} compare case")
    _require(compare.get("missing_or_empty_field_behavior"), "FAIL_CLOSED", f"{label} compare missing")
    _require(compare.get("top_level_operator_allowed"), False, f"{label} compare top-level")

    development = _mapping(record.get("development_rechecks"), f"{label} development")
    socbed = _mapping(development.get("socbed"), f"{label} SOCBED")
    _require(socbed.get("candidate_findings_on_exact_event"), 1, f"{label} SOCBED finding")
    _require(socbed.get("candidate_rule_id"), "R-MASQUERADE-ORIGINAL-NAME-MISMATCH", f"{label} SOCBED rule")
    _require(socbed.get("source_specific_signature_used"), False, f"{label} source specificity")
    _require(socbed.get("attack_recall_interpretation_allowed"), False, f"{label} recall boundary")

    atomic = _mapping(development.get("atomic_evtx_t1036"), f"{label} Atomic")
    for key, expected in {
        "selected_file_count": 13,
        "sysmon_event1": 345,
        "basename_mismatch_events": 50,
        "refined_predicate_hits": 9,
        "selected_files_with_refined_hits": 7,
    }.items():
        _require(atomic.get(key), expected, f"{label} Atomic {key}")
    _require(atomic.get("selected_file_set_sha256"), "d9ddf4e145ef74d1c48582251514a9a93b2af752b2a093963356430988776f8b", f"{label} Atomic manifest")
    _require(atomic.get("event_level_true_positive_claim"), False, f"{label} Atomic TP boundary")

    win10 = _mapping(development.get("nextron_win10"), f"{label} Win10")
    _require(win10.get("historical_sysmon_event1"), 2149, f"{label} Win10 Event1")
    _require(win10.get("preregistered_refined_predicate_hits"), 0, f"{label} Win10 prereg hits")
    recheck = _mapping(win10.get("implementation_recheck"), f"{label} Win10 recheck")
    for key, expected in {
        "sysmon_records_covered_exactly_once": 732200,
        "raw_parent_records": 5861,
        "event1_parent_candidates": 17,
        "basename_mismatch_parent_candidates": 0,
        "refined_predicate_hits": 0,
    }.items():
        _require(recheck.get(key), expected, f"{label} Win10 {key}")
    _require(recheck.get("chunk_range_covered"), "0:11894", f"{label} Win10 chunks")

    win11 = _mapping(development.get("nextron_win11"), f"{label} Win11")
    for key, expected in {
        "sysmon_event1": 2323,
        "basename_mismatch_events": 227,
        "suspicious_location_mismatch_events": 37,
        "refined_predicate_hits": 0,
    }.items():
        _require(win11.get(key), expected, f"{label} Win11 {key}")

    combined = _mapping(development.get("combined_nextron"), f"{label} combined benign")
    _require(combined.get("sysmon_event1"), 4472, f"{label} combined Event1")
    _require(combined.get("refined_predicate_hits"), 0, f"{label} combined hits")
    _require(combined.get("confirmed_true_negatives"), "NOT_CLAIMED", f"{label} TN boundary")
    _require(combined.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} FPR boundary")

    decision = _mapping(record.get("decision"), f"{label} decision")
    _require(decision.get("implementation"), "ACCEPTED_FOR_CURRENT_RULEPACK", f"{label} decision")
    _require(decision.get("fresh_current_rulepack_performance_available"), False, f"{label} fresh performance")

    claims = _mapping(record.get("claim_boundary"), f"{label} claims")
    _require(claims.get("posthoc_development_change"), True, f"{label} posthoc")
    _require(claims.get("fresh_validation"), False, f"{label} fresh")
    _require(claims.get("prior_p2_25_attack_revalidation_applies_to_current_rulepack"), False, f"{label} prior attack applicability")
    _require(claims.get("prior_p2_26c_benign_revalidation_applies_to_current_rulepack"), False, f"{label} prior benign applicability")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} production FPR")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", f"{label} production accuracy")

    return P35I_HASH, {
        "remediation_id": P35I_ID,
        "detector_repo_commit": P35I_COMMIT,
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": P35I_HASH,
        "change_class": "posthoc_attack_gap_remediation",
        "rule_count_before": 68,
        "rule_count_after": 69,
        "socbed_known_gap_findings": 1,
        "atomic_refined_predicate_hits": 9,
        "nextron_combined_event1": 4472,
        "nextron_refined_predicate_hits": 0,
        "fresh_attack_revalidation": "NOT_RUN",
        "fresh_benign_revalidation": "NOT_RUN",
        "production_false_positive_rate": "NOT_CLAIMED",
    }


def _verify_cmdgap(
    repo: Path,
    record: Mapping[str, Any],
    previous_hash: str,
) -> tuple[str, dict[str, Any]]:
    label = "CMDGAP"
    _require(
        record.get("schema"),
        "breachscope.independent_command_coverage_remediation.v1",
        f"{label} schema",
    )
    _require(record.get("analysis_id"), CMDGAP_ID, f"{label} analysis id")
    _require(
        record.get("status"),
        "IMPLEMENTED_POSTHOC_PENDING_FRESH_REVALIDATION",
        f"{label} status",
    )
    _require(
        record.get("analysis_class"),
        "POSTHOC_DEVELOPMENT_REMEDIATION_NOT_FRESH_VALIDATION",
        f"{label} class",
    )

    basis = _mapping(record.get("basis"), f"{label} basis")
    _require(basis.get("brawl_canonical_result_modified"), False, f"{label} canonical modified")
    _require(basis.get("brawl_canonical_rerun"), False, f"{label} canonical rerun")
    _require(
        basis.get("rule_semantics_basis"),
        "INDEPENDENT_PUBLIC_DOCUMENTATION_AND_SYNTHETIC_FIXTURES",
        f"{label} semantic basis",
    )
    _require(basis.get("brawl_score_optimization_target"), False, f"{label} score target")

    remediation = _mapping(record.get("remediation"), f"{label} remediation")
    _require(remediation.get("remediation_id"), CMDGAP_ID, f"{label} remediation id")
    _require(
        remediation.get("change_class"),
        "posthoc_gap_remediation_with_independent_semantic_support",
        f"{label} change class",
    )
    _require(remediation.get("detector_repo_commit"), CMDGAP_COMMIT, f"{label} detector commit")
    _require(remediation.get("from_rules_tree_sha256"), previous_hash, f"{label} from hash")
    _require(remediation.get("to_rules_tree_sha256"), CMDGAP_HASH, f"{label} to hash")
    _require(remediation.get("rule_count_before"), 69, f"{label} rule count before")
    _require(remediation.get("rule_count_after"), 73, f"{label} rule count after")
    _require(remediation.get("rule_file_count"), 5, f"{label} rule file count")
    _require(remediation.get("fresh_attack_revalidation"), "NOT_RUN", f"{label} attack")
    _require(remediation.get("fresh_benign_revalidation"), "NOT_RUN", f"{label} benign")

    files = remediation.get("changed_rule_files")
    if not isinstance(files, list) or len(files) != 2:
        raise CurrentEvidenceError(f"{label} must record exactly two changed rule files")
    file_map = {
        str(row.get("path")): str(row.get("git_blob_sha1"))
        for row in files
        if isinstance(row, Mapping)
    }
    _require(
        file_map,
        {
            "rules/example_safe.yml": CMDGAP_EXAMPLE_BLOB,
            "rules/p2_20_postholdout_rules.yml": CMDGAP_P20_BLOB,
        },
        f"{label} changed file blobs",
    )
    _require(
        _git_blob_at_commit(repo, CMDGAP_COMMIT, "rules/example_safe.yml"),
        CMDGAP_EXAMPLE_BLOB,
        f"{label} detector-commit example_safe blob",
    )
    _require(
        _git_blob_at_commit(repo, CMDGAP_COMMIT, "rules/p2_20_postholdout_rules.yml"),
        CMDGAP_P20_BLOB,
        f"{label} detector-commit P2-20 blob",
    )

    _require(
        remediation.get("modified_rule_ids"),
        ["R-WMI-Create", "R-REG-RunKey"],
        f"{label} modified rule ids",
    )
    expected_added = [
        "R-NETWORK-CONFIG-NBTSTAT",
        "R-PERMISSION-GROUPS-LOCAL-NET",
        "R-PERMISSION-GROUPS-DOMAIN-NET",
        "R-SMB-ADMIN-SHARE-NET-USE",
    ]
    _require(remediation.get("added_rule_ids"), expected_added, f"{label} added rule ids")

    wmi = legacy._load_rule(repo, "rules/example_safe.yml", "R-WMI-Create")
    _require(wmi.get("operator"), "regex", f"{label} WMI operator")
    _require(
        wmi.get("pattern"),
        r"(?i)\bwmic(?:\.exe)?\b.*\bprocess\s+call\s+create\b",
        f"{label} WMI pattern",
    )
    _require(wmi.get("mitre_technique"), "T1047", f"{label} WMI technique")

    run_key = legacy._load_rule(repo, "rules/example_safe.yml", "R-REG-RunKey")
    _require(run_key.get("operator"), "regex", f"{label} Run-key operator")
    _require(
        run_key.get("pattern"),
        r"(?i)\breg(?:\.exe)?\s+add\s+(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b",
        f"{label} Run-key pattern",
    )
    _require(run_key.get("mitre_technique"), "T1547.001", f"{label} Run-key technique")

    expected_rules = {
        "R-NETWORK-CONFIG-NBTSTAT": "T1016",
        "R-PERMISSION-GROUPS-LOCAL-NET": "T1069.001",
        "R-PERMISSION-GROUPS-DOMAIN-NET": "T1069.002",
        "R-SMB-ADMIN-SHARE-NET-USE": "T1021.002",
    }
    for rule_id, technique in expected_rules.items():
        live = legacy._load_rule(repo, "rules/p2_20_postholdout_rules.yml", rule_id)
        _require(live.get("field"), "command_line", f"{label} {rule_id} field")
        _require(live.get("operator"), "regex", f"{label} {rule_id} operator")
        _require(live.get("mitre_technique"), technique, f"{label} {rule_id} technique")
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

    development = _mapping(record.get("development_validation"), f"{label} development")
    synthetic = _mapping(
        development.get("independent_synthetic_tests"),
        f"{label} synthetic",
    )
    _require(synthetic.get("status"), "PASS", f"{label} synthetic status")
    _require(synthetic.get("passed"), 10, f"{label} synthetic passed")
    _require(synthetic.get("failed"), 0, f"{label} synthetic failed")
    related = _mapping(development.get("related_regression"), f"{label} related")
    _require(related.get("status"), "PASS", f"{label} related status")
    _require(related.get("passed"), 47, f"{label} related passed")
    _require(related.get("failed"), 0, f"{label} related failed")

    brawl = _mapping(
        development.get("brawl_posthoc_development_recheck"),
        f"{label} BRAWL development recheck",
    )
    _require(
        brawl.get("class"),
        "POSTHOC_DEVELOPMENT_ONLY_NOT_FRESH_VALIDATION",
        f"{label} BRAWL class",
    )
    _require(brawl.get("rules_frozen_before_recheck"), True, f"{label} frozen before recheck")
    _require(brawl.get("canonical_result_recomputed"), False, f"{label} canonical recompute")
    _require(brawl.get("canonical_result_replaced"), False, f"{label} canonical replace")
    _require(brawl.get("prior_findings"), 44, f"{label} prior findings")
    _require(brawl.get("post_remediation_findings"), 89, f"{label} post findings")
    pair_diag = _mapping(brawl.get("post_pair_diagnostic"), f"{label} pair diagnostic")
    _require(pair_diag.get("frozen_pair_count"), 133, f"{label} pair count")
    _require(pair_diag.get("would_meet_frozen_hit_dimensions"), 1, f"{label} would-hit")
    _require(
        pair_diag.get("expected_technique_same_host_outside_window"),
        23,
        f"{label} outside-window",
    )
    _require(
        pair_diag.get("telemetry_present_no_expected_technique_finding"),
        100,
        f"{label} no-technique finding",
    )
    _require(
        pair_diag.get("no_normalized_telemetry_in_frozen_window"),
        9,
        f"{label} no telemetry",
    )

    claims = _mapping(record.get("claim_boundary"), f"{label} claims")
    _require(claims.get("posthoc_development_change"), True, f"{label} posthoc")
    _require(claims.get("fresh_validation"), False, f"{label} fresh")
    _require(
        claims.get("prior_p2_35m_revalidation_applies_to_current_rulepack"),
        False,
        f"{label} P2-35M applicability",
    )
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} FPR")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", f"{label} accuracy")

    return CMDGAP_HASH, {
        "remediation_id": CMDGAP_ID,
        "detector_repo_commit": CMDGAP_COMMIT,
        "from_rules_tree_sha256": previous_hash,
        "to_rules_tree_sha256": CMDGAP_HASH,
        "change_class": "posthoc_gap_remediation_with_independent_semantic_support",
        "rule_count_before": 69,
        "rule_count_after": 73,
        "fresh_attack_revalidation": "NOT_RUN",
        "fresh_benign_revalidation": "NOT_RUN",
        "production_false_positive_rate": "NOT_CLAIMED",
    }


def _verify_p2_35m(repo: Path, row: Mapping[str, Any]) -> dict[str, Any]:
    label = "P2-35M"
    _require(row.get("revalidation_id"), P35M_ID, f"{label} chain id")
    _require(row.get("class"), "fresh_current_rulepack_attack_and_benign_source_revalidation", f"{label} class")
    _require(row.get("result_record"), P35M_RESULT_RECORD, f"{label} result record")
    _require(row.get("measurement_record"), P35M_RAW, f"{label} raw record")
    _require(row.get("permanent_lock_record"), P35M_LOCK, f"{label} lock record")
    _require(row.get("detector_repo_commit"), P35M_PRODUCT_COMMIT, f"{label} detector commit")
    _require(row.get("detector_rules_tree_sha256"), P35I_HASH, f"{label} detector hash")
    _require(row.get("rule_count"), 69, f"{label} rule count")
    _require(row.get("fresh_attack_revalidation"), "COMPLETED", f"{label} attack completion")
    _require(row.get("fresh_benign_revalidation"), "COMPLETED", f"{label} benign completion")
    _require(row.get("independent_source_family_holdout"), False, f"{label} independent holdout")
    _require(row.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} production FPR")
    _require(row.get("production_recall"), "NOT_CLAIMED", f"{label} production recall")

    summary = legacy._load_yaml(
        legacy._relative_file(repo, P35M_RESULT_RECORD, f"{label} summary")
    )
    _require(summary.get("schema"), "breachscope.p2_35m_current_rulepack_fresh_source_revalidation_result.v1", f"{label} summary schema")
    _require(summary.get("analysis_id"), P35M_ANALYSIS_ID, f"{label} summary analysis id")
    _require(summary.get("status"), "COMPLETED", f"{label} summary status")

    raw = _locked_json(repo, P35M_RAW, P35M_RAW_SHA, f"{label} raw")
    _require(raw.get("schema"), "breachscope.p2_35m_current_rulepack_fresh_source_revalidation.v1", f"{label} raw schema")
    _require(raw.get("analysis_id"), P35M_ANALYSIS_ID, f"{label} raw analysis id")
    _require(raw.get("status"), "completed", f"{label} raw status")
    _require(raw.get("contract_sha256"), P35M_CONTRACT_SHA, f"{label} contract SHA")
    _require(raw.get("runner_sha256"), P35M_RUNNER_SHA, f"{label} runner SHA")

    frozen = _mapping(raw.get("frozen_product"), f"{label} frozen product")
    _require(frozen.get("repo_commit"), P35M_PRODUCT_COMMIT, f"{label} product commit")
    _require(frozen.get("rules_tree_sha256"), P35I_HASH, f"{label} rule hash")
    _require(frozen.get("rule_count"), 69, f"{label} raw rule count")
    _require(frozen.get("rule_file_count"), 5, f"{label} raw rule file count")

    lock_path = legacy._relative_file(repo, P35M_LOCK, f"{label} lock")
    _require(_sha256(lock_path), P35M_LOCK_SHA, f"{label} lock SHA")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    _require(lock.get("analysis_id"), P35M_ANALYSIS_ID, f"{label} lock analysis id")

    source = _mapping(raw.get("source_verification"), f"{label} source")
    attack_source = _mapping(source.get("attack"), f"{label} attack source")
    datasets = attack_source.get("datasets")
    if not isinstance(datasets, list) or len(datasets) != 10:
        raise CurrentEvidenceError(f"{label} must contain exactly ten attack identities")
    if not all(x.get("size_match") and x.get("git_blob_match") and x.get("sha256_match") for x in datasets):
        raise CurrentEvidenceError(f"{label} attack source identity mismatch")
    archive = _mapping(source.get("benign_archive"), f"{label} benign archive")
    _require(archive.get("filename"), "win2022-ad.tgz", f"{label} archive name")
    _require(archive.get("size_match"), True, f"{label} archive size")
    _require(archive.get("sha256_match"), True, f"{label} archive SHA")

    attack = _mapping(raw.get("attack_revalidation"), f"{label} attack")
    a = _mapping(attack.get("summary"), f"{label} attack summary")
    for key, expected in {
        "fixture_count": 10, "hits": 6, "misses": 4, "errors": 0,
        "fixture_hit_rate": 0.6, "expected_technique_matches": 1,
        "expected_technique_nonmatches": 9, "expected_technique_errors": 0,
        "expected_technique_match_fraction_of_all_fixtures": 0.1,
        "expected_technique_match_fraction_of_evaluable_fixtures": 0.1,
    }.items():
        _require(a.get(key), expected, f"{label} attack {key}")

    benign = _mapping(raw.get("benign_revalidation"), f"{label} benign")
    b = _mapping(benign.get("summary"), f"{label} benign summary")
    for key, expected in {
        "evtx_member_count": 337, "raw_records": 425986, "parsed_events": 425974,
        "parse_errors": 12, "findings": 4, "flagged_events": 4,
    }.items():
        _require(b.get(key), expected, f"{label} benign {key}")
    _require(b.get("observed_source_intent_benign_flagged_event_fraction"), 9.390244475014907e-06, f"{label} benign fraction")
    _require(b.get("observed_source_intent_benign_flagged_event_percent"), 0.0009390244475014907, f"{label} benign percent")
    _require(b.get("findings_by_rule"), {"R-WMI-WMIPRVSE-CHILD-4688": 4}, f"{label} benign rules")
    members = benign.get("members")
    if not isinstance(members, list) or len(members) != 337:
        raise CurrentEvidenceError(f"{label} must contain exactly 337 benign members")
    flagged = [x for x in members if x.get("flagged_events")]
    if len(flagged) != 1:
        raise CurrentEvidenceError(f"{label} must contain exactly one flagged benign member")
    _require(flagged[0].get("name"), "Win2022-AD/Security.evtx", f"{label} flagged member")
    _require(flagged[0].get("flagged_events"), 4, f"{label} flagged count")

    claims = _mapping(raw.get("claim_boundary"), f"{label} claims")
    _require(claims.get("attack_fixture_hit_rate_is_event_level_recall"), False, f"{label} fixture recall")
    _require(claims.get("attack_source_path_technique_match_is_event_level_recall"), False, f"{label} technique recall")
    _require(claims.get("flagged_benign_events_are_confirmed_false_positives"), False, f"{label} confirmed FP")
    _require(claims.get("confirmed_false_positive_rate"), "NOT_CLAIMED", f"{label} confirmed FPR")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", f"{label} production FPR")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", f"{label} production accuracy")
    _require(claims.get("production_recall"), "NOT_CLAIMED", f"{label} production recall")
    _require(claims.get("independent_source_family_holdout"), False, f"{label} holdout")

    return {
        "revalidation_id": P35M_ID,
        "detector_repo_commit": P35M_PRODUCT_COMMIT,
        "detector_rules_tree_sha256": P35I_HASH,
        "fixture_count": 10, "hits": 6, "misses": 4, "errors": 0,
        "fixture_hit_rate": 0.6, "expected_technique_matches": 1,
        "expected_technique_match_fraction": 0.1,
        "fixture_hit_rate_is_event_level_recall": False,
        "expected_technique_match_fraction_is_event_level_recall": False,
        "benign_evtx_member_count": 337, "benign_parsed_events": 425974,
        "benign_parse_errors": 12, "benign_findings": 4, "benign_flagged_events": 4,
        "observed_source_intent_benign_flagged_event_fraction": 9.390244475014907e-06,
        "observed_source_intent_benign_flagged_event_percent": 0.0009390244475014907,
        "flagged_events_are_confirmed_false_positives": False,
        "fresh_attack_revalidation": "COMPLETED",
        "fresh_benign_revalidation": "COMPLETED",
        "independent_source_family_holdout": False,
        "production_false_positive_rate": "NOT_CLAIMED",
        "production_recall": "NOT_CLAIMED",
    }


def verify(repo: Path, chain_path: Path) -> dict[str, Any]:
    live_current_chain = legacy._load_yaml(chain_path)
    _require(live_current_chain.get("schema"), CHAIN_SCHEMA, "current evidence schema")
    _require(
        live_current_chain.get("current_evidence_id"),
        CMDGAP_CURRENT_ID,
        "current evidence id",
    )

    live_rows = live_current_chain.get("post_remediation_revalidations")
    if not isinstance(live_rows, list) or len(live_rows) != 3:
        raise CurrentEvidenceError(
            "post_remediation_revalidations must contain P2-25, P2-26C, then P2-35M"
        )
    p35m = _verify_p2_35m(repo, _mapping(live_rows[2], "P2-35M chain row"))

    live_posthoc_rows = live_current_chain.get("posthoc_remediations")
    if not isinstance(live_posthoc_rows, list) or len(live_posthoc_rows) != 3:
        raise CurrentEvidenceError(
            "posthoc_remediations must contain P2-24D, P2-35I, then CMDGAP"
        )
    cmdgap_row = _mapping(live_posthoc_rows[2], "CMDGAP chain row")
    _require(cmdgap_row.get("remediation_id"), CMDGAP_ID, "CMDGAP chain id")
    _require(
        cmdgap_row.get("remediation_record"),
        CMDGAP_RECORD,
        "CMDGAP chain record",
    )
    _require(
        cmdgap_row.get("change_class"),
        "posthoc_gap_remediation_with_independent_semantic_support",
        "CMDGAP chain class",
    )
    _require(
        cmdgap_row.get("detector_repo_commit"),
        CMDGAP_COMMIT,
        "CMDGAP chain commit",
    )
    _require(
        cmdgap_row.get("from_rules_tree_sha256"),
        P35I_HASH,
        "CMDGAP chain from hash",
    )
    _require(
        cmdgap_row.get("to_rules_tree_sha256"),
        CMDGAP_HASH,
        "CMDGAP chain to hash",
    )
    _require(
        cmdgap_row.get("fresh_attack_revalidation"),
        "NOT_RUN",
        "CMDGAP chain attack",
    )
    _require(
        cmdgap_row.get("fresh_benign_revalidation"),
        "NOT_RUN",
        "CMDGAP chain benign",
    )

    cmdgap_path = legacy._relative_file(
        repo,
        cmdgap_row.get("remediation_record"),
        "CMDGAP remediation",
    )
    cmdgap_record = legacy._load_yaml(cmdgap_path)
    current_from_record, cmdgap = _verify_cmdgap(repo, cmdgap_record, P35I_HASH)
    _require(current_from_record, CMDGAP_HASH, "CMDGAP verified rule hash")

    current_hash, current_rule_file_count = legacy.historical._rules_tree_hash(
        repo / "rules"
    )
    _require(current_hash, CMDGAP_HASH, "live current rule tree")
    _require(current_rule_file_count, 5, "live current rule file count")

    live_detector = _mapping(
        live_current_chain.get("current_frozen_detector"),
        "live current frozen detector",
    )
    _require(live_detector.get("repo_commit"), CMDGAP_COMMIT, "live detector commit")
    _require(
        live_detector.get("rules_tree_sha256"),
        CMDGAP_HASH,
        "live detector rule hash",
    )
    _require(live_detector.get("rule_count"), 73, "live detector rule count")
    _require(live_detector.get("rule_file_count"), 5, "live detector rule file count")

    live_validation = _mapping(
        live_current_chain.get("current_rulepack_validation"),
        "live current rulepack validation",
    )
    _require(live_validation.get("rule_change_id"), CMDGAP_ID, "live validation rule change")
    _require(
        live_validation.get("current_revalidation_id"),
        "NOT_RUN",
        "live validation revalidation",
    )
    _require(
        live_validation.get("fresh_attack_revalidation_after_current_rule_change"),
        "NOT_RUN",
        "live validation attack",
    )
    _require(
        live_validation.get("fresh_benign_revalidation_after_current_rule_change"),
        "NOT_RUN",
        "live validation benign",
    )
    _require(
        live_validation.get("prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack"),
        False,
        "live validation prior P2-25/P2-26C applicability",
    )
    _require(
        live_validation.get("prior_p2_35m_revalidation_applies_to_current_rulepack"),
        False,
        "live validation P2-35M applicability",
    )
    _require(
        live_validation.get("fresh_current_rulepack_performance_available"),
        False,
        "live validation performance",
    )

    live_claims = _mapping(
        live_current_chain.get("claim_boundary"),
        "live current evidence claims",
    )
    _require(live_claims.get("production_accuracy"), "NOT_CLAIMED", "production accuracy")
    _require(
        live_claims.get("production_false_positive_rate"),
        "NOT_CLAIMED",
        "production FPR",
    )
    _require(live_claims.get("production_recall"), "NOT_CLAIMED", "production recall")
    _require(
        live_claims.get("fresh_full_benign_fpr_for_current_rulepack"),
        "NOT_CLAIMED",
        "fresh full benign FPR",
    )

    # Reconstruct the exact P2-35M-era live chain in memory. This preserves the
    # byte-exact historical result while allowing the repository's live rules
    # to move forward to the 73-rule CMDGAP remediation.
    p35m_chain = copy.deepcopy(live_current_chain)
    p35m_chain["current_evidence_id"] = P35M_CURRENT_ID
    p35m_chain["current_frozen_detector"] = {
        "repo_commit": P35I_COMMIT,
        "rules_tree_sha256": P35I_HASH,
        "rule_count": 69,
        "rule_file_count": 5,
    }
    p35m_chain["posthoc_remediations"] = live_posthoc_rows[:2]
    p35m_chain["current_rulepack_validation"] = {
        "rule_change_id": P35I_ID,
        "current_revalidation_id": P35M_ID,
        "fresh_attack_revalidation_after_current_rule_change": "COMPLETED",
        "fresh_benign_revalidation_after_current_rule_change": "COMPLETED",
        "prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack": False,
        "fresh_current_rulepack_performance_available": True,
    }

    _require(p35m_chain.get("current_evidence_id"), P35M_CURRENT_ID, "P2-35M historical current id")
    historical_rows = p35m_chain.get("post_remediation_revalidations")
    if not isinstance(historical_rows, list) or len(historical_rows) != 3:
        raise CurrentEvidenceError(
            "historical post_remediation_revalidations must contain P2-25, P2-26C, then P2-35M"
        )
    historical_validation = _mapping(
        p35m_chain.get("current_rulepack_validation"),
        "P2-35M historical current rulepack validation",
    )
    _require(historical_validation.get("rule_change_id"), P35I_ID, "P2-35M validation rule change")
    _require(historical_validation.get("current_revalidation_id"), P35M_ID, "P2-35M validation revalidation")
    _require(
        historical_validation.get("fresh_attack_revalidation_after_current_rule_change"),
        "COMPLETED",
        "P2-35M validation attack",
    )
    _require(
        historical_validation.get("fresh_benign_revalidation_after_current_rule_change"),
        "COMPLETED",
        "P2-35M validation benign",
    )
    _require(
        historical_validation.get("fresh_current_rulepack_performance_available"),
        True,
        "P2-35M validation performance",
    )

    # Rewind once more to the P2-35I post-remediation/pre-revalidation point
    # and verify the entire older chain under its historical invariants.
    chain = copy.deepcopy(p35m_chain)
    chain["current_evidence_id"] = P35I_CURRENT_ID
    chain["post_remediation_revalidations"] = historical_rows[:2]
    chain["current_rulepack_validation"] = {
        "rule_change_id": P35I_ID,
        "fresh_attack_revalidation_after_current_rule_change": "NOT_RUN",
        "fresh_benign_revalidation_after_current_rule_change": "NOT_RUN",
        "prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack": False,
        "fresh_current_rulepack_performance_available": False,
    }
    _require(chain.get("schema"), CHAIN_SCHEMA, "historical current evidence schema")
    _require(chain.get("current_evidence_id"), P35I_CURRENT_ID, "historical current evidence id")

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
    _require(
        [row.get("calibration_id") for row in calibrations],
        expected_ids,
        "calibration chain order/content",
    )

    history = _verify_history_through_h(repo, chain)
    j_path = legacy._relative_file(
        repo,
        calibrations[5].get("measurement_record"),
        "P2-11J measurement",
    )
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
    if not isinstance(posthoc_rows, list) or len(posthoc_rows) != 2:
        raise CurrentEvidenceError("posthoc_remediations must contain P2-24D then P2-35I")
    posthoc_row = _mapping(posthoc_rows[0], "P2-24D chain row")
    _require(posthoc_row.get("remediation_id"), P24D_ID, "P2-24D chain id")
    _require(posthoc_row.get("from_rules_tree_sha256"), p20_hash, "P2-24D chain from hash")
    _require(posthoc_row.get("to_rules_tree_sha256"), P24D_HASH, "P2-24D chain to hash")
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
    if not isinstance(revalidation_rows, list) or len(revalidation_rows) != 2:
        raise CurrentEvidenceError(
            "post_remediation_revalidations must contain P2-25 then P2-26C"
        )
    p25_row = _mapping(revalidation_rows[0], "P2-25 chain row")
    p25 = _verify_p2_25(repo, p25_row)
    p26c_row = _mapping(revalidation_rows[1], "P2-26C chain row")
    p26c = _verify_p2_26c(repo, p26c_row)

    p29 = _verify_p2_29_parser_maintenance(repo, chain)

    p35i_row = _mapping(posthoc_rows[1], "P2-35I chain row")
    _require(p35i_row.get("remediation_id"), P35I_ID, "P2-35I chain id")
    _require(p35i_row.get("detector_repo_commit"), P35I_COMMIT, "P2-35I chain commit")
    _require(p35i_row.get("from_rules_tree_sha256"), final_hash, "P2-35I chain from hash")
    _require(p35i_row.get("to_rules_tree_sha256"), P35I_HASH, "P2-35I chain to hash")
    _require(p35i_row.get("fresh_attack_revalidation"), "NOT_RUN", "P2-35I chain attack")
    _require(p35i_row.get("fresh_benign_revalidation"), "NOT_RUN", "P2-35I chain benign")
    p35i_path = legacy._relative_file(
        repo,
        p35i_row.get("remediation_record"),
        "P2-35I remediation",
    )
    p35i_record = legacy._load_yaml(p35i_path)
    final_hash, p35i = _verify_p2_35i(repo, p35i_record, final_hash)

    _require(final_hash, P35I_HASH, "historical P2-35I rule tree explained by chain")
    detector = _mapping(chain.get("current_frozen_detector"), "historical current frozen detector")
    _require(detector.get("repo_commit"), P35I_COMMIT, "historical detector commit")
    _require(detector.get("rules_tree_sha256"), P35I_HASH, "historical detector rule hash")
    _require(detector.get("rule_count"), 69, "historical detector rule count")
    _require(detector.get("rule_file_count"), 5, "historical detector rule file count")

    current_validation = _mapping(
        chain.get("current_rulepack_validation"),
        "historical current rulepack validation",
    )
    _require(current_validation.get("rule_change_id"), P35I_ID, "historical validation rule change")
    _require(
        current_validation.get("fresh_attack_revalidation_after_current_rule_change"),
        "NOT_RUN",
        "historical validation attack",
    )
    _require(
        current_validation.get("fresh_benign_revalidation_after_current_rule_change"),
        "NOT_RUN",
        "historical validation benign",
    )
    _require(
        current_validation.get("fresh_current_rulepack_performance_available"),
        False,
        "historical validation performance",
    )

    claims = _mapping(chain.get("claim_boundary"), "historical current evidence claims")
    _require(claims.get("production_accuracy"), "NOT_CLAIMED", "historical production accuracy")
    _require(
        claims.get("production_false_positive_rate"),
        "NOT_CLAIMED",
        "historical production FPR",
    )
    _require(claims.get("final_blind_holdout"), False, "historical final blind holdout")
    _require(
        claims.get("fresh_full_benign_fpr_for_current_rulepack"),
        "NOT_CLAIMED",
        "historical fresh full benign FPR",
    )

    return {
        "schema": "breachscope.current_detection_evidence_verification.v13",
        "current_evidence_id": live_current_chain.get("current_evidence_id"),
        "status": "PASS",
        "base_rules_tree_sha256": history["base_rules_tree_sha256"],
        "current_rules_tree_sha256": current_hash,
        "rule_file_count": current_rule_file_count,
        "base_attack_scenario_hits": history["base_attack_scenario_hits"],
        "current_attack_scenario_hits": history["current_attack_scenario_hits"],
        "current_attack_scenario_hits_applies_to_current_rulepack": False,
        "attack_scenario_total": history["attack_scenario_total"],
        "fresh_attack_revalidation_after_current_rule_change": "NOT_RUN",
        "fresh_benign_revalidation_after_current_rule_change": "NOT_RUN",
        "prior_revalidations_apply_to_current_rulepack": False,
        "prior_p2_35m_revalidation_applies_to_current_rulepack": False,
        "prior_attack_fixture_hits": p25["hits"],
        "prior_attack_fixture_total": p25["fixture_count"],
        "prior_attack_fixture_hit_rate": p25["fixture_hit_rate"],
        "prior_benign_parsed_events": p26c["parsed_events"],
        "prior_benign_parse_errors": p26c["parse_errors"],
        "prior_benign_flagged_events": p26c["flagged_events"],
        "prior_benign_findings": p26c["findings"],
        "prior_benign_observed_flagged_event_fraction": p26c[
            "observed_source_intent_benign_flagged_event_fraction"
        ],
        "prior_benign_observed_flagged_event_percent": p26c[
            "observed_source_intent_benign_flagged_event_percent"
        ],
        "historical_benign": history["historical_benign"],
        "remediations": history["remediations"],
        "calibrations": [*history["calibrations"], j, p20],
        "posthoc_remediations": [p24d, p35i, cmdgap],
        "post_remediation_revalidations": [p25, p26c, p35m],
        "parser_maintenance": [p29],
        "current_rulepack_validation": {
            "rule_change_id": CMDGAP_ID,
            "current_revalidation_id": "NOT_RUN",
            "fresh_attack_revalidation_after_current_rule_change": "NOT_RUN",
            "fresh_benign_revalidation_after_current_rule_change": "NOT_RUN",
            "prior_p2_25_p2_26c_revalidations_apply_to_current_rulepack": False,
            "prior_p2_35m_revalidation_applies_to_current_rulepack": False,
            "fresh_current_rulepack_performance_available": False,
        },
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
        print(
            "Fresh attack revalidation after current rule change: "
            f"{result['fresh_attack_revalidation_after_current_rule_change']}"
        )
        print(
            "Fresh benign revalidation after current rule change: "
            f"{result['fresh_benign_revalidation_after_current_rule_change']}"
        )
        print(
            "Prior P2-25/P2-26C revalidations apply to current rulepack: "
            f"{result['prior_revalidations_apply_to_current_rulepack']}"
        )
        print("Fresh full benign FPR for current rulepack: NOT CLAIMED")
        print("Production accuracy/FPR: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
