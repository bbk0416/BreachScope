from __future__ import annotations
import hashlib, json
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
SUMMARY=ROOT/"external_baseline"/"p2_35m_current_rulepack_fresh_source_revalidation_result.yaml"
RAW=ROOT/"external_baseline"/"results"/"p2_35m_4aa6a1d"/"result.json"
LOCK=ROOT/"external_baseline"/"locks"/"P2_35M_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
CONTRACT=ROOT/"external_baseline"/"p2_35m_current_rulepack_fresh_source_revalidation_contract.yaml"
RUNNER=ROOT/"scripts"/"p2_35m_current_rulepack_fresh_source_revalidation.py"
CURRENT=ROOT/"external_baseline"/"current_detection_evidence.yaml"
ATTRS=ROOT/".gitattributes"
def _sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def _y(p): return yaml.safe_load(p.read_text(encoding="utf-8"))
def _j(p): return json.loads(p.read_text(encoding="utf-8"))
def test_p2_35m_canonical_artifacts_are_byte_exact():
    s=_y(SUMMARY); assert s["status"]=="COMPLETED"; assert RAW.stat().st_size==169648; assert LOCK.stat().st_size==122
    assert _sha(RAW)=="14a3143f5b674c97685910ff1040ba92f3bd7bd80e262598adeb71f59bcce9e0"
    assert _sha(LOCK)=="e374b17549707b97173c42aa852abb51e611d2c5d1c774a7e54ecbcc0c2a0f0f"
def test_p2_35m_raw_result_freezes_current_69_rule_detector():
    r=_j(RAW); assert r["status"]=="completed"; assert r["analysis_id"]=="p2-35m-current-rulepack-fresh-source-revalidation-v1"
    assert r["contract_sha256"]==_sha(CONTRACT); assert r["runner_sha256"]==_sha(RUNNER)
    assert r["frozen_product"]=={"repo_commit":"2401f8b9b6a569b8b932451f0a0ae20ffa26abbc","rules_tree_sha256":"1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7","rule_count":69,"rule_file_count":5}
def test_p2_35m_attack_revalidation_is_6_of_10_but_not_recall():
    r=_j(RAW); s=r["attack_revalidation"]["summary"]; assert s["fixture_count"]==10 and s["hits"]==6 and s["misses"]==4 and s["errors"]==0 and s["fixture_hit_rate"]==0.6
    assert s["expected_technique_matches"]==1 and s["expected_technique_match_fraction_of_all_fixtures"]==0.1
    c=r["claim_boundary"]; assert c["attack_fixture_hit_rate_is_event_level_recall"] is False; assert c["attack_source_path_technique_match_is_event_level_recall"] is False; assert c["production_recall"]=="NOT_CLAIMED"
def test_p2_35m_benign_revalidation_preserves_source_intent_boundary():
    r=_j(RAW); s=r["benign_revalidation"]["summary"]; assert s["evtx_member_count"]==337 and s["parsed_events"]==425974 and s["parse_errors"]==12 and s["findings"]==4 and s["flagged_events"]==4
    assert s["findings_by_rule"]=={"R-WMI-WMIPRVSE-CHILD-4688":4}; f=[x for x in r["benign_revalidation"]["members"] if x["flagged_events"]]; assert len(f)==1 and f[0]["name"]=="Win2022-AD/Security.evtx" and f[0]["flagged_events"]==4
    c=r["claim_boundary"]; assert c["flagged_benign_events_are_confirmed_false_positives"] is False; assert c["confirmed_false_positive_rate"]=="NOT_CLAIMED"; assert c["production_false_positive_rate"]=="NOT_CLAIMED"
def test_p2_35m_remains_historical_after_new_rulepack_remediation():
    c=_y(CURRENT); v=c["current_rulepack_validation"]; assert c["current_evidence_id"]=="independent-command-coverage-remediation-current-detection-evidence"
    assert v["current_revalidation_id"]=="NOT_RUN"; assert v["fresh_attack_revalidation_after_current_rule_change"]=="NOT_RUN"; assert v["fresh_benign_revalidation_after_current_rule_change"]=="NOT_RUN"; assert v["prior_p2_35m_revalidation_applies_to_current_rulepack"] is False; assert v["fresh_current_rulepack_performance_available"] is False
    m=c["post_remediation_revalidations"][-1]; assert m["revalidation_id"]=="p2-35m-current-rulepack-fresh-source-revalidation"; assert m["detector_rules_tree_sha256"]=="1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"; assert m["detector_rules_tree_sha256"]!=c["current_frozen_detector"]["rules_tree_sha256"]; assert m["fixture_count"]==10 and m["hits"]==6 and m["expected_technique_matches"]==1; assert m["benign_parsed_events"]==425974 and m["benign_flagged_events"]==4; assert m["independent_source_family_holdout"] is False
def test_p2_35m_artifacts_are_configured_for_byte_exact_git_storage():
    a=ATTRS.read_text(encoding="utf-8"); assert "external_baseline/locks/P2_35M_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock -text -whitespace" in a; assert "external_baseline/results/p2_35m_4aa6a1d/result.json -text -eol -whitespace" in a
