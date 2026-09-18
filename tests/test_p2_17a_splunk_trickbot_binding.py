from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_17a_splunk_trickbot_binding.yaml"


def _load():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_p2_17a_freezes_code_and_rules_before_observation():
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_holdout_binding"
    code = row["code_under_observation"]
    assert code["repo_commit"] == "05cae988d780200f547325a92c42c053b86f11b9"
    assert code["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert code["rule_count"] == 66


def test_p2_17a_binds_exact_splunk_trickbot_bytes():
    source = _load()["source_binding"]
    assert source["repository"] == "splunk/attack_data"
    assert source["pinned_commit"] == "db9624b71def9902600972593abf0dfaf9f3b399"
    assert source["dataset_directory"] == "datasets/malware/trickbot/infection"
    assert source["metadata_sha256"] == "ca655e395cc90a6dffde9f067df0be65a76967287b8dbb22df82d7b4df2e5d02"
    assert source["telemetry_sha256"] == "94438dd32541ebd0150f782ba6dcce8fbd12d7c592013d3426c8bb0bb24ae24d"
    assert source["telemetry_size_bytes"] == 463822959
def test_p2_17a_selection_remained_pre_observation():
    selection = _load()["selection_basis"]
    assert selection["breachscope_search_for_attack_data_or_trickbot_before_binding"] == 0
    assert selection["selected_from_repository_path_metadata_only"] is True
    assert selection["metadata_yaml_contents_inspected_before_binding"] is False
    assert selection["telemetry_contents_inspected_before_binding"] is False


def test_p2_17a_protocol_is_one_pass_and_frozen():
    protocol = _load()["protocol"]
    assert protocol["corpus_previously_used_for_breachscope_development"] is False
    assert protocol["corpus_previously_measured_by_breachscope"] is False
    assert protocol["implementation_frozen_before_source_observation"] is True
    assert protocol["rules_frozen_before_source_observation"] is True
    assert protocol["one_pass_measurement_planned"] is True
    assert protocol["tuning_after_source_observation_before_measurement_allowed"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False


def test_p2_17a_does_not_preclaim_quality_metrics():
    boundary = _load()["claim_boundary"]
    assert boundary["event_level_ground_truth"] == "NOT_ASSESSED_BEFORE_BINDING"
    for key in (
        "detection_precision", "detection_recall", "false_positive_rate",
        "chain_precision", "chain_recall", "scenario_precision",
        "scenario_recall", "scenario_accuracy", "production_quality",
    ):
        assert boundary[key] == "NOT_CLAIMED"
