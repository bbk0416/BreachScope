from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_17a_trickbot_infection_binding.yaml"


def _load():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_p2_17a_freezes_code_rules_and_source_before_observation():
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_holdout_binding"
    assert row["code_under_observation"]["repo_commit"] == "05cae988d780200f547325a92c42c053b86f11b9"
    assert row["code_under_observation"]["rule_count"] == 66
    source = row["source_binding"]
    assert source["repository"] == "splunk/attack_data"
    assert source["pinned_commit"] == "db9624b71def9902600972593abf0dfaf9f3b399"
    assert source["metadata_sha256"] == "ca655e395cc90a6dffde9f067df0be65a76967287b8dbb22df82d7b4df2e5d02"


def test_p2_17a_binds_exact_telemetry_without_preinspection():
    row = _load()
    source = row["source_binding"]
    assert source["telemetry_git_lfs_oid_sha256"] == "94438dd32541ebd0150f782ba6dcce8fbd12d7c592013d3426c8bb0bb24ae24d"
    assert source["telemetry_size_bytes"] == 463822959
    selection = row["selection_basis"]
    assert selection["metadata_file_contents_inspected_before_binding"] is False
    assert selection["telemetry_contents_inspected_before_binding"] is False
    assert selection["breachscope_default_branch_search_for_attack_data_or_trickbot"] == 0


def test_p2_17a_protocol_is_one_pass_and_does_not_preclaim_metrics():
    row = _load()
    protocol = row["protocol"]
    assert protocol["corpus_previously_used_for_breachscope_development"] is False
    assert protocol["corpus_previously_measured_by_breachscope"] is False
    assert protocol["one_pass_measurement_planned"] is True
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    boundary = row["claim_boundary"]
    for key in ("detection_precision", "detection_recall", "false_positive_rate",
                "chain_precision", "chain_recall", "scenario_precision",
                "scenario_recall", "scenario_accuracy", "production_quality"):
        assert boundary[key] == "NOT_CLAIMED"
