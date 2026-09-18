from pathlib import Path
import hashlib
import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_17c_locked_attack_data_bundle_binding.yaml"
RUNNER = ROOT / "scripts" / "p2_17c_locked_one_pass.py"

EXPECTED = {
    "T1003.001": ("a1905850598f1e943708c3329190e29c6cb046389c1575cb2afd6369b5f269f1", 14235927),
    "T1021.006": ("6370f139b06c5de9e6b76ba81d9247c7c869879e74dfee1603f4d8b3682ab1c4", 5835542),
    "T1087.002": ("1b78f515120a7e5ac532444fd7fd322c8dc1abf8efebe0295abad3939972db0d", 10902926),
    "T1105": ("bd6bbf7884f44274988d159bcb3249505dc53623e551892b54a3fc87db06e18c", 3625178),
    "T1490": ("b2d2d3e6a15185fa73e7ace39dd57a3d499f65a462f7101b215161e1ccbb8e96", 510708),
}

def load():
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))

def test_p2_17c_freezes_product_rules_and_runner():
    row = load()
    code = row["code_under_observation"]
    assert code["repo_commit"] == "b842066e7815bff0186a46c897692ad4bd196c1e"
    assert code["rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert code["rule_count"] == 66
    actual = hashlib.sha256(RUNNER.read_bytes()).hexdigest()
    assert row["runner"]["sha256"] == actual
    assert row["runner"]["permanent_exclusive_lock"] is True
    assert row["runner"]["atomic_stage_persistence"] is True

def test_p2_17c_binds_five_fresh_exact_sources():
    row = load()
    assert row["selection_policy"]["technique_ids"] == list(EXPECTED)
    assert row["selection_policy"]["metadata_yaml_semantics_inspected_before_binding"] is False
    assert row["selection_policy"]["telemetry_contents_inspected_before_binding"] is False
    datasets = row["datasets"]
    assert len(datasets) == 5
    for item in datasets:
        sha, size = EXPECTED[item["technique_id"]]
        assert item["telemetry_sha256"] == sha
        assert item["telemetry_size_bytes"] == size
        assert item["local_filename"]

def test_p2_17c_protocol_forbids_duplicate_and_result_driven_reruns():
    row = load()
    protocol = row["protocol"]
    assert protocol["runner_frozen_before_telemetry_observation"] is True
    assert protocol["duplicate_execution_prevented_by_permanent_lock"] is True
    assert protocol["tuning_after_telemetry_observation_before_measurement_allowed"] is False
    assert protocol["no_result_driven_remeasurement"] is True
    assert protocol["p2_14e_final_blind_holdout_rerun"] is False
def test_p2_17c_runner_contract_is_fail_closed_and_atomic():
    source = RUNNER.read_text(encoding="utf-8")
    assert "os.O_CREAT | os.O_EXCL | os.O_WRONLY" in source
    assert "one-pass lock already exists" in source
    assert "os.replace(temp, path)" in source
    for stage in ("source_verified", "parsed", "detected", "correlated", "completed"):
        assert stage in source
    assert "lock.unlink" not in source
    assert "os.remove(lock" not in source

def test_p2_17c_claim_boundary_is_narrow():
    row = load()
    claims = row["claim_boundary"]
    assert claims["event_level_ground_truth"] == "NOT_AVAILABLE"
    assert claims["path_label_dataset_hit_rate"] == "MEASURABLE_AFTER_ONE_PASS"
    assert claims["path_label_dataset_hit_rate_is_event_level_recall"] is False
    for key in ("detection_precision", "detection_recall", "false_positive_rate",
                "chain_precision", "chain_recall", "scenario_accuracy", "production_quality"):
        assert claims[key] == "NOT_CLAIMED"
