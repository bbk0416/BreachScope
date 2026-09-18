from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "p2_17b_attack_data_technique_bundle_binding.yaml"

EXPECTED = {
    "T1059.001": ("8f71b2a0ef81892551cd6a9ad115b8ec5c42d9f2071547b064c496511898c4e9", 38928903),
    "T1543.003": ("2e6ea9e053a84f4d32b37f462a40a39f1a90c2049adaf684b0660ee6e9f32d7a", 11281916),
    "T1053.005": ("d346ab6c75b3151217dfc2c4c166c951fc16d68c31b7d5a8f3e577d9545ff9f0", 11410982),
    "T1047": ("64651720e10813aa57d0f25ce149005ab06039b1974dbc09818b1fb45fbbc196", 11815541),
    "T1218.011": ("0805f7d8a89371dee4f75c001ef11574c2d759d91626c1625bca7c9174cfe29f", 23784139),
}


def _load():
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_binding_freezes_current_code_and_rules():
    row = _load()
    code = row["code_under_observation"]
    assert code["repo_commit"] == "34e4d4440f57d4c8a83f77da60807458a71816c8"
    assert code["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert code["rule_count"] == 66


def test_selection_is_deterministic_and_pre_observation():
    row = _load()
    policy = row["selection_policy"]
    assert policy["technique_ids"] == list(EXPECTED)
    assert policy["selected_directory_for_all"] == "atomic_red_team"
    assert policy["source_path_is_dataset_level_expected_technique"] is True
    assert policy["metadata_yaml_contents_inspected_before_binding"] is False
    assert policy["telemetry_contents_inspected_before_binding"] is False


def test_exact_five_telemetry_objects_are_bound():
    rows = _load()["datasets"]
    assert len(rows) == 5
    assert {row["technique_id"] for row in rows} == set(EXPECTED)
    for row in rows:
        sha, size = EXPECTED[row["technique_id"]]
        assert row["telemetry_path"].endswith("/atomic_red_team/windows-sysmon.log")
        assert row["telemetry_sha256"] == sha
        assert row["telemetry_size_bytes"] == size


def test_protocol_forbids_result_driven_tuning_and_rerun():
    row = _load()
    protocol = row["protocol"]
    assert protocol["corpus_previously_used_for_breachscope_development"] is False
    assert protocol["corpus_previously_measured_by_breachscope"] is False
    assert protocol["implementation_frozen_before_telemetry_observation"] is True
    assert protocol["rules_frozen_before_telemetry_observation"] is True
    assert protocol["tuning_after_telemetry_observation_before_measurement_allowed"] is False
    assert row["measurement_contract"]["no_result_driven_remeasurement"] is True
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False


def test_claim_boundary_does_not_turn_path_labels_into_recall():
    row = _load()
    contract = row["measurement_contract"]
    claims = row["claim_boundary"]
    assert contract["path_label_hit_rate_is_event_level_recall"] is False
    assert claims["event_level_ground_truth"] == "NOT_AVAILABLE"
    assert claims["path_label_dataset_hit_rate"] == "MEASURABLE_AFTER_ONE_PASS"
    assert claims["detection_precision"] == "NOT_CLAIMED"
    assert claims["detection_recall"] == "NOT_CLAIMED"
    assert claims["production_quality"] == "NOT_CLAIMED"
