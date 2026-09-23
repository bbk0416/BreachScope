from pathlib import Path

import yaml

from breachscope.rules import load_rules


ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT = ROOT / "external_baseline" / "p2_35h_named_run_key_rule_assessment.yaml"
P2_35G = ROOT / "external_baseline" / "p2_35g_socbed_clock_offset_binding_result.yaml"


def _load() -> dict:
    return yaml.safe_load(ASSESSMENT.read_text(encoding="utf-8"))


def test_p2_35h_candidate_is_rejected_and_not_in_product_rules() -> None:
    row = _load()
    assert row["status"] == "CANDIDATE_REJECTED_NO_GO"
    assert row["decision"]["candidate_rule"] == "NO_GO"
    assert row["decision"]["product_rule_change"] == "REVERTED_NOT_MERGED"
    assert row["candidate_rule"]["product_merge_performed"] is False
    assert row["candidate_rule"]["candidate_reverted_before_assessment_commit"] is True
    assert "R-RUNKEY-NAMED-13" not in {rule.id for rule in load_rules(ROOT / "rules")}


def test_p2_35h_preserves_current_rule_tree_and_rule_count() -> None:
    row = _load()
    assert row["decision"]["current_rules_tree_preserved"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert row["decision"]["current_rule_count_preserved"] == 68
    assert row["candidate_rule"]["candidate_rule_count"] == 69
    assert row["candidate_rule"]["candidate_rules_tree_sha256"] == (
        "ec872a19c98ead8b0cec6c250c980cbb8d7ca2adc268ce0a87dcd965d22914f2"
    )
    assert row["candidate_rule"]["synthetic_targeted_tests"] == {
        "passed": 8,
        "failed": 0,
    }


def test_p2_35h_benign_probe_is_bound_to_exact_public_source() -> None:
    row = _load()["benign_noise_probe"]
    source = row["source"]
    assert source["asset_size_bytes"] == 169_460_461
    assert source["asset_sha256"] == (
        "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
    )
    evtx = row["extracted_sysmon_evtx"]
    assert evtx["size_bytes"] == 2_359_365_632
    assert evtx["sha256"] == (
        "cac4ff5e97c0605d7f64878cb89e81374a663b18763ccd94529414da1e6407df"
    )


def test_p2_35h_generic_candidate_has_observed_benign_noise() -> None:
    row = _load()["benign_noise_probe"]
    result = row["results"]
    assert result["sysmon_event13_records"] == 175_364
    assert result["setvalue_records"] == 175_364
    assert result["candidate_named_run_runonce_matches"] == 16
    assert result["unique_target_objects"] == 15
    assert result["unnamed_run_runonce_matches"] == 0
    assert result["confirmed_false_positives"] == "NOT_CLAIMED"
    assert result["operational_noise_risk"] == (
        "OBSERVED_ON_SOURCE_INTENT_BENIGN_CORPUS"
    )
    names = [entry["target_object"] for entry in row["matched_targets"]]
    assert any("AvastUI.exe" in value for value in names)
    assert any("GoogleDriveFS" in value for value in names)
    assert any("Discord" in value for value in names)
    assert any("KeePass 2 PreLoad" in value for value in names)


def test_p2_35h_keeps_socbed_gaps_factual_without_recall_claim() -> None:
    row = _load()
    gap = row["observed_gap"]
    assert gap["misc_set_autostart"]["posthoc_known_event_count"] == 2
    assert gap["misc_set_autostart"]["frozen_findings_on_known_events"] == 0
    assert gap["misc_execute_malware"]["posthoc_known_event_count"] == 1
    assert gap["misc_execute_malware"]["frozen_findings_on_known_events"] == 0
    assert gap["misc_execute_malware"]["disposition"] == (
        "REMAINS_DOCUMENTED_GAP_NO_RULE_ADDED"
    )
    assert row["claim_boundary"]["attack_level_recall"] == "NOT_EVALUATED"
    assert row["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"

    predecessor = yaml.safe_load(P2_35G.read_text(encoding="utf-8"))
    assert predecessor["decision"]["misc_set_autostart"] == "0_OF_2_EVENTS_WITH_FINDINGS"
    assert predecessor["decision"]["misc_execute_malware"] == "0_OF_1_EVENTS_WITH_FINDINGS"
