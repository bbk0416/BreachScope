from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "external_baseline" / "results" / "p2_12d_f6c76614" / "post-result-taxonomy.json"
MEASUREMENT = ROOT / "external_baseline" / "results" / "p2_12d_f6c76614" / "measurement.yaml"


def test_p2_12d_artifact_bytes_and_status_counts_are_locked() -> None:
    assert hashlib.sha256(RESULT.read_bytes()).hexdigest() == (
        "b9b121023c1cfb649c51672cb3a138e1ede4202f731f17ca9b6029e6754b063d"
    )
    d = json.loads(RESULT.read_text(encoding="utf-8"))
    assert d["schema"] == "breachscope.p2_12d_day1_post_result_taxonomy.v1"
    assert d["analysis_class"] == "post_result_descriptive_analysis"
    assert d["day2_accessed"] is False
    assert d["source_id_status_counts_v19_2"] == {
        "active": 27,
        "deprecated": 1,
        "missing": 0,
        "revoked": 17,
    }
    assert d["officially_replaced_source_id_count"] == 17
    assert d["resolvable_source_id_count"] == 44


def test_p2_12d_preserves_fresh_result_and_only_reports_post_result_semantics() -> None:
    d = json.loads(RESULT.read_text(encoding="utf-8"))
    fresh = d["fresh_precommitted_result_preserved"]
    assert fresh["source_legacy_id_total"] == 45
    assert fresh["exact_legacy_id_overlap"] == ["T1140"]
    assert fresh["exact_legacy_id_overlap_count"] == 1
    assert d["post_result_semantic_source_match_count"] == 5

    pairs = {
        (row["source_id"], row["effective_current_id"], tuple(row["matched_observed_ids"]))
        for row in d["post_result_semantic_source_matches"]
    }
    assert pairs == {
        ("T1003", "T1003", ("T1003.001",)),
        ("T1035", "T1569.002", ("T1569.002",)),
        ("T1059", "T1059", ("T1059.001",)),
        ("T1086", "T1059.001", ("T1059.001",)),
        ("T1140", "T1140", ("T1140",)),
    }
    assert d["matched_observed_detector_ids"] == [
        "T1003.001",
        "T1059.001",
        "T1140",
        "T1569.002",
    ]
    assert d["unmatched_observed_detector_ids"] == ["T1087.002", "T1127.001"]

    claim = d["claim_boundary"]
    assert claim["fresh_primary_metric_recomputed"] is False
    assert claim["post_result_semantic_match_is_fresh_metric"] is False
    assert claim["production_recall"] == "NOT_CLAIMED"


def test_p2_12d_measurement_keeps_day2_unseen_and_no_detector_rerun() -> None:
    m = yaml.safe_load(MEASUREMENT.read_text(encoding="utf-8"))
    assert m["analysis_class"] == "post_result_descriptive_analysis"
    assert m["execution"]["github_actions_run_id"] == 34663944588
    assert m["execution"]["artifact_id"] == 10288347710
    assert m["execution"]["artifact_digest_sha256"] == (
        "b52637b4fc01465f23dedca75ede5a64f90bc9879a52f50c93001d83c8105d3f"
    )
    assert m["observations"]["fresh_precommitted_exact_overlap_count"] == 1
    assert m["observations"]["post_result_semantic_source_match_count"] == 5
    assert m["protocol_state"] == {
        "day2_accessed": False,
        "day2_scored": False,
        "detector_rerun_for_p2_12d": False,
        "fresh_primary_metric_recomputed": False,
    }
    assert m["claim_boundary"]["fresh_external_holdout_exact_overlap"] == "1/45"
    assert m["claim_boundary"]["post_result_semantic_match_is_fresh_metric"] is False
