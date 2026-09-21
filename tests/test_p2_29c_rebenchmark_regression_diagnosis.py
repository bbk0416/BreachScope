from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "performance" / "p2_29c_rebenchmark_regression_diagnosis.yaml"


def _load() -> dict:
    return yaml.safe_load(RECORD.read_text(encoding="utf-8"))


def test_p2_29c_keeps_both_canonical_results_immutable() -> None:
    row = _load()
    assert row["status"] == "CLOSE_POSTHOC_NO_CAUSAL_ATTRIBUTION_NO_ROLLBACK"
    decision = row["decision"]
    assert decision["p2_29b_canonical_regression_observation_retained"] is True
    assert decision["p2_28_canonical_result_modified"] is False
    assert decision["p2_29b_canonical_result_modified"] is False
    assert decision["rerun_p2_28_or_p2_29b_under_same_benchmark_id"] is False


def test_p2_29c_runtime_change_scope_is_only_ingest_for_product_paths() -> None:
    scope = _load()["runtime_change_scope"]
    assert scope["changed_runtime_paths"] == ["breachscope/ingest.py"]
    assert scope["rules_changed"] is False
    assert scope["parser_change"] == (
        "two ElementTree parses to one shared parsed root"
    )


def test_p2_29c_posthoc_outputs_match_exactly() -> None:
    probe = _load()["development_posthoc_probe"]
    assert probe["records_per_run"] == 2000
    assert probe["order"] == ["old", "new", "new", "old"]
    assert probe["normalized_output_mismatches"] == 0
    assert probe["output_digest_sha256_all_runs"] == (
        "fb7e3d23b424688a0757966d532d271799b1299d1899a740e3ca3b1845c7a922"
    )
    assert probe["formal_benchmark"] is False
    assert probe["speedup_claim_allowed"] is False


def test_p2_29c_posthoc_parser_does_not_reproduce_regression() -> None:
    probe = _load()["development_posthoc_probe"]
    assert probe["old_parser_average_seconds"] == 1.8453615000180434
    assert probe["new_parser_average_seconds"] == 1.6102939500124194
    assert probe["old_over_new_parser_ratio"] == 1.1459780371178885
    assert probe["new_parser_average_change_percent"] == -12.738292741196
    assert probe["new_parser_average_seconds"] < probe["old_parser_average_seconds"]


def test_p2_29c_records_large_record_xml_timing_variation() -> None:
    probe = _load()["development_posthoc_probe"]
    assert probe["record_xml_min_seconds"] == 15.411098700016737
    assert probe["record_xml_max_seconds"] == 25.03074519999791
    assert probe["record_xml_max_over_min_ratio"] == 1.6242025106211748
    assert probe["record_xml_max_over_min_ratio"] > 1.6


def test_p2_29c_does_not_make_causal_or_general_performance_claim() -> None:
    row = _load()
    decision = row["decision"]
    claim = row["claim_boundary"]
    assert decision["rollback_single_parse_refactor"] == "NO"
    assert decision["general_speedup_claim"] == "NOT_CLAIMED"
    assert decision["general_slowdown_claim"] == "NOT_CLAIMED"
    assert claim["causal_attribution_to_single_parse_refactor"] == "NOT_ESTABLISHED"
    assert claim["parser_level_regression"] == (
        "NOT_OBSERVED_IN_DEVELOPMENT_POSTHOC_PROBE"
    )
    assert claim["p2_29b_whole_run_regression"] == (
        "OBSERVED_IN_ONE_CANONICAL_PAIRED_RUN"
    )
    assert claim["statistical_benchmark"] is False


def test_p2_29c_next_measurement_is_new_repeated_stage_level_design() -> None:
    decision = _load()["decision"]
    text = decision["next_measurement_design"]
    assert "new repeated stage-level benchmark" in text
    assert "record.xml" in text
    assert "warm/cold cache" in text
