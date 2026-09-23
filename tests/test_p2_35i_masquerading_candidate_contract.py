from pathlib import Path

import yaml

from breachscope.rules import load_rules


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35i_masquerading_candidate_contract.yaml"
P2_35G = ROOT / "external_baseline" / "p2_35g_socbed_clock_offset_binding_result.yaml"
P2_35H = ROOT / "external_baseline" / "p2_35h_named_run_key_rule_assessment.yaml"
PLANNED_RULE_ID = "R-MASQUERADE-ORIGINAL-NAME-MISMATCH"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_35i_is_preregistered_development_candidate_only() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_DEVELOPMENT_REMEDIATION_CANDIDATE"
    assert row["analysis_class"] == "POSTHOC_DEVELOPMENT_CANDIDATE_NOT_FRESH_VALIDATION"
    assert row["decision"]["candidate"] == "GO_FOR_IMPLEMENTATION"
    assert row["decision"]["product_merge"] == "NOT_YET_AUTHORIZED"
    assert row["claim_boundary"]["fresh_validation"] is False
    assert row["claim_boundary"]["independent_holdout_performance"] == "NOT_EVALUATED"


def test_p2_35i_freezes_current_product_before_mutation() -> None:
    row = _load()
    frozen = row["frozen_product_before_candidate"]
    assert frozen["repo_commit"] == "ae9d70b45c491f2ffa236ca7875c2d808061227b"
    assert frozen["rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert frozen["rule_count"] == 68
    assert frozen["rule_file_count"] == 5

    by_id = {rule.id for rule in load_rules(ROOT / "rules")}
    assert len(by_id) == 68
    assert PLANNED_RULE_ID not in by_id


def test_p2_35i_refined_predicate_is_exact_and_source_independent() -> None:
    row = _load()
    predicate = row["candidate_predicate"]
    assert predicate["provider"] == "Microsoft-Windows-Sysmon"
    assert predicate["event_id"] == "1"
    assert predicate["executable_field"] == "canonical.process.executable"
    assert predicate["original_file_name_field"] == "OriginalFileName"
    assert predicate["parent_executable_field"] == "canonical.process.parent_executable"
    assert predicate["executable_basename_relation"] == "NOT_EQUALS_CASE_INSENSITIVE"
    assert predicate["planned_mitre_technique"] == "T1036.003"
    assert predicate["planned_severity"] == "medium"

    implementation_text = " ".join(
        [
            predicate["provider"],
            predicate["executable_field"],
            predicate["original_file_name_field"],
            predicate["parent_executable_field"],
            predicate["executable_location_regex"],
            predicate["parent_executable_regex"],
            row["planned_implementation"]["field_compare_operator"]["name"],
            row["planned_implementation"]["product_rule"]["planned_id"],
        ]
    ).casefold()
    for token in predicate["forbidden_source_specific_tokens"]:
        assert token.casefold() not in implementation_text


def test_p2_35i_development_evidence_is_frozen_without_accuracy_claims() -> None:
    evidence = _load()["development_evidence"]

    win10 = evidence["nextron_win10_benign"]
    assert win10["sysmon_records"] == 732_200
    assert win10["sysmon_event1"] == 2_149
    assert win10["basename_mismatch_events"] == 89
    assert win10["suspicious_location_mismatch_events"] == 25
    assert win10["refined_predicate_hits"] == 0
    assert win10["asset_sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert win10["sysmon_evtx_sha256"] == (
        "efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb"
    )

    win11 = evidence["nextron_win11_benign"]
    assert win11["sysmon_event1"] == 2_323
    assert win11["basename_mismatch_events"] == 227
    assert win11["suspicious_location_mismatch_events"] == 37
    assert win11["refined_predicate_hits"] == 0
    assert win11["asset_sha256"] == (
        "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
    )
    assert win11["sysmon_evtx_sha256"] == (
        "cac4ff5e97c0605d7f64878cb89e81374a663b18763ccd94529414da1e6407df"
    )

    combined = evidence["combined_benign"]
    assert combined["sysmon_event1"] == 4_472
    assert combined["refined_predicate_hits"] == 0
    assert combined["confirmed_true_negatives"] == "NOT_CLAIMED"
    assert combined["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_35i_atomic_and_socbed_positive_development_evidence_is_bounded() -> None:
    evidence = _load()["development_evidence"]

    atomic = evidence["atomic_evtx_t1036"]
    assert atomic["pinned_commit"] == "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
    assert atomic["selected_sysmon_json_file_count"] == 13
    assert atomic["selected_file_set_sha256_method"] == ("SHA256 of sorted UTF-8 lines path<TAB>file_sha256<TAB>size_bytes<LF>")
    assert atomic["selected_file_set_sha256"] == (
        "d9ddf4e145ef74d1c48582251514a9a93b2af752b2a093963356430988776f8b"
    )
    assert atomic["sysmon_event1"] == 345
    assert atomic["basename_mismatch_events"] == 50
    assert atomic["refined_predicate_hits"] == 9
    assert atomic["selected_files_with_refined_hits"] == 7
    assert atomic["event_level_labels_available"] is False

    socbed = evidence["socbed"]
    assert socbed["refined_predicate_hits_on_known_execute_gap"] == 1
    assert socbed["positive_unit_is_posthoc_known_event"] is True


def test_p2_35i_implementation_and_claim_boundaries_fail_closed() -> None:
    row = _load()
    impl = row["planned_implementation"]
    assert impl["canonical_process_fallback"]["must_not_override_existing_legacy_fields"] is True
    compare = impl["field_compare_operator"]
    assert compare["name"] == "basename_not_equals_field"
    assert compare["scope"] == "ALL_OF_ONLY"
    assert compare["case_insensitive"] is True
    assert compare["empty_or_missing_field_behavior"] == "FAIL_CLOSED"
    assert compare["top_level_operator_allowed"] is False
    assert impl["product_rule"]["source_specific_literals_allowed"] is False

    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_product_mutation"] is True
    assert protocol["implementation_must_follow_exact_predicate"] is True
    assert protocol["result_driven_predicate_tuning_after_contract_merge_allowed"] is False
    assert protocol["product_rule_merge_requires_current_evidence_chain_update"] is True
    assert protocol["fresh_post_change_revalidation_required_before_claiming_current_rulepack_performance"] is True

    claim = row["claim_boundary"]
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["attack_level_recall"] == "NOT_EVALUATED"
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["atomic_refined_hits_are_event_level_true_positives"] is False
    assert claim["nextron_zero_matches_are_confirmed_true_negatives"] is False

    p2_35g = yaml.safe_load(P2_35G.read_text(encoding="utf-8"))
    p2_35h = yaml.safe_load(P2_35H.read_text(encoding="utf-8"))
    assert p2_35g["decision"]["misc_execute_malware"] == "0_OF_1_EVENTS_WITH_FINDINGS"
    assert p2_35h["decision"]["candidate_rule"] == "NO_GO"


def test_p2_35i_atomic_file_manifest_recomputes_frozen_digest() -> None:
    import hashlib

    atomic = _load()["development_evidence"]["atomic_evtx_t1036"]
    manifest = atomic["selected_file_manifest"]
    assert len(manifest) == 13
    paths = [row["path"] for row in manifest]
    assert paths == sorted(paths)
    payload = "".join(
        f"{row['path']}\t{row['sha256']}\t{row['size_bytes']}\n"
        for row in manifest
    ).encode("utf-8")
    assert hashlib.sha256(payload).hexdigest() == atomic["selected_file_set_sha256"]
    assert atomic["selected_file_set_sha256"] == (
        "d9ddf4e145ef74d1c48582251514a9a93b2af752b2a093963356430988776f8b"
    )


def test_p2_35i_apt29_context_is_identity_bound_but_not_positive_evidence() -> None:
    apt = _load()["development_evidence"]["apt29_day1_context"]
    assert apt["pinned_commit"] == "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
    assert apt["archive_size_bytes"] == 13_944_973
    assert apt["archive_sha256"] == (
        "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5"
    )
    assert apt["sysmon_event1"] == 447
    assert apt["basename_mismatch_events"] == 25
    assert apt["event_level_labels_available"] is False
    assert apt["refined_predicate_not_used_as_positive_claim"] is True
    assert "legacy_source_plan_contains_t1036" not in apt
