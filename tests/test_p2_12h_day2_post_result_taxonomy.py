from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "external_baseline" / "results" / "p2_12h_d0b58a98" / "post-result-taxonomy.json"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_12h_d0b58a98" / "measurement.yaml"
SCRIPT = ROOT / "scripts" / "p2_12h_post_result_taxonomy.py"


def test_p2_12h_preserves_confirmatory_primary_result() -> None:
    d = json.loads(RESULT.read_text(encoding="utf-8"))
    preserved = d["confirmatory_precommitted_result_preserved"]
    assert preserved["source_legacy_id_total"] == 41
    assert preserved["exact_legacy_id_overlap_count"] == 1
    assert preserved["exact_legacy_id_overlap"] == ["T1047"]
    assert preserved["interpretation"].endswith("not recall.")
    assert d["detector_rerun"] is False


def test_p2_12h_uses_only_pinned_official_attack_taxonomy() -> None:
    d = json.loads(RESULT.read_text(encoding="utf-8"))
    attack = d["attack_reference"]
    assert attack["repository"] == "mitre-attack/attack-stix-data"
    assert attack["commit"] == "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
    assert attack["release"] == "Enterprise ATT&CK v19.2"
    assert attack["sha256"] == "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
    assert d["source_id_status_counts_v19_2"] == {"active": 25, "revoked": 15, "deprecated": 1, "missing": 0}
    assert d["officially_replaced_source_id_count"] == 15
    assert d["resolvable_source_id_count"] == 40


def test_p2_12h_semantic_matches_are_exact_and_post_result_only() -> None:
    d = json.loads(RESULT.read_text(encoding="utf-8"))
    assert d["post_result_semantic_source_match_count"] == 6
    triples = {(x["source_id"], x["effective_current_id"], x["matched_observed_ids"][0]) for x in d["post_result_semantic_source_matches"]}
    assert triples == {
        ("T1003", "T1003", "T1003.001"),
        ("T1027", "T1027", "T1027.010"),
        ("T1028", "T1021.006", "T1021.006"),
        ("T1047", "T1047", "T1047"),
        ("T1086", "T1059.001", "T1059.001"),
        ("T1136", "T1136", "T1136.001"),
    }
    assert d["unmatched_observed_detector_ids"] == ["T1053.005", "T1087.002"]
    claims = d["claim_boundary"]
    assert claims["confirmatory_primary_metric_recomputed"] is False
    assert claims["post_result_semantic_match_is_confirmatory_metric"] is False
    assert claims["independent_fresh_external_holdout"] is False
    assert claims["production_recall"] == "NOT_CLAIMED"


def test_p2_12h_execution_evidence_is_locked() -> None:
    d = json.loads(RESULT.read_text(encoding="utf-8"))
    e = d["execution_evidence"]
    assert e["github_actions_run_id"] == 34672968876
    assert e["workflow_control_head_commit"] == "07ca8b86bb5ed901463b534152fb94ce4fc9ffb6"
    assert e["artifact_id"] == 10291551792
    assert e["artifact_digest_sha256"] == "76ce16f50b827ce1abd325ab0e45aacb407f58e045b686bc46de812e75ea3a51"
    assert e["artifact_inner_full_taxonomy_sha256"] == "5ea92bfc026dc47ef0db8eece9a2796ce5e623a9d1488075627708c224e9fb79"
    assert e["artifact_inner_full_taxonomy_bytes"] == 12037


def test_p2_12h_measurement_and_script_preserve_boundaries() -> None:
    m = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    assert m["measurement_class"] == "post_result_descriptive_analysis"
    assert m["protocol"]["result_observed_before_analysis"] is True
    assert m["protocol"]["detector_rerun"] is False
    assert m["protocol"]["detector_or_rule_change"] is False
    assert m["protocol"]["post_result_mapping_used_for_primary_metric"] is False
    assert m["claim_boundary"]["confirmatory_primary_metric_recomputed"] is False
    assert m["claim_boundary"]["post_result_semantic_match_is_confirmatory_metric"] is False
    assert m["claim_boundary"]["production_recall"] == "NOT_CLAIMED"
    text = SCRIPT.read_text(encoding="utf-8")
    assert "revoked-by" in text
    assert "ATTACK_SHA256" in text
    assert "apply_rules" not in text
    assert "load_rules" not in text
