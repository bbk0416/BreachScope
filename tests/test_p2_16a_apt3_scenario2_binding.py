from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_16a_apt3_scenario2_binding.yaml"


def _load():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_p2_16a_freezes_code_and_rules_before_observation():
    row = _load()
    assert row["analysis_class"] == "pre_observation_external_holdout_binding"
    assert row["code_under_observation"]["repo_commit"] == "4514279c0b223483016acf35009ed2985f6a016e"
    assert row["code_under_observation"]["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert row["code_under_observation"]["rule_count"] == 66


def test_p2_16a_binds_exact_apt3_scenario2_artifacts():
    source = _load()["source_binding"]
    assert source["repository"] == "OTRF/Security-Datasets"
    assert source["pinned_commit"] == "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
    assert source["archive_path"].endswith("/empire_apt3.tar.gz")
    assert source["archive_size_bytes"] == 28948319
    assert source["archive_sha256"] == "ab4d1ec4e44102c87946a974f93aa248e49e5001e01fac3f137ec7e61bbc18ed"
    assert source["playbook_size_bytes"] == 82963
    assert source["playbook_sha256"] == "903d4c576bbb47f75ec8ddc13b4e34e8a63ab2d8edbb5160e24a654ab64fd2b7"


def test_p2_16a_protocol_is_blind_and_one_pass():
    row = _load()
    protocol = row["protocol"]
    assert protocol["corpus_previously_used_for_breachscope_development"] is False
    assert protocol["corpus_previously_measured_by_breachscope"] is False
    assert protocol["implementation_frozen_before_raw_observation"] is True
    assert protocol["rules_frozen_before_raw_observation"] is True
    assert protocol["blind_reconstruction_evaluation_planned"] is True
    assert protocol["one_pass_measurement_planned"] is True
    assert protocol["tuning_after_raw_observation_before_measurement_allowed"] is False
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False


def test_p2_16a_selection_did_not_open_bound_artifacts():
    selection = _load()["selection_basis"]
    assert selection["breachscope_default_branch_search_for_apt3_before_binding"] == 0
    assert selection["raw_archive_contents_inspected_before_binding"] is False
    assert selection["playbook_cells_inspected_before_binding"] is False


def test_p2_16a_does_not_preclaim_accuracy_metrics():
    boundary = _load()["claim_boundary"]
    assert boundary["event_level_ground_truth"] == "NOT_ASSESSED_BEFORE_BINDING"
    for key in ("detection_precision", "detection_recall", "chain_precision", "chain_recall", "scenario_precision", "scenario_recall", "scenario_accuracy", "production_quality"):
        assert boundary[key] == "NOT_CLAIMED"
