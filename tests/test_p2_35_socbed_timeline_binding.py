from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_35_socbed_timeline_binding.yaml"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_35_is_preobservation_and_freezes_current_product() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_BEFORE_DATA_OBSERVATION"
    frozen = row["frozen_product"]
    assert frozen["repo_commit"] == "3ca80865477cccfa5e967f549acf32d92182eccd"
    assert frozen["rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert frozen["rule_file_count"] == 5
    assert frozen["rule_count"] == 68
    assert frozen["product_or_rules_change_before_measurement_allowed"] is False


def test_p2_35_pins_exact_socbed_source_metadata() -> None:
    row = _load()["source"]
    assert row["repository"] == "fkie-cad/socbed-eval-acsac-2021"
    assert row["pinned_commit"] == "c264060f0e65ea69c2d891525ae835a543f851ca"
    assert row["pinned_tree"] == "12c20febfb81251c5cb21a79d89cdf6db94e28ae"
    assert row["readme"]["git_blob_sha1"] == "44c888c139b3cd4c29781a95963038b6405aff69"
    assert row["readme"]["sha256"] == (
        "876ef2b7ed0a76039306cf6840456eed7b494a488b9420cb3a65f7a4c53aaf91"
    )
    assert row["schedule"]["git_blob_sha1"] == "501c32e41196d56d0d6b4d67d963edf10e4156a3"
    assert row["schedule"]["sha256"] == (
        "1ae844300d87af32af55b3ae1c8f881e1d3e424c3b7cf51051c61df3fa76837c"
    )
    assert row["dataset_archive"]["size_bytes"] == 77_984_817
    assert row["dataset_archive"]["git_blob_sha1"] == (
        "270ea757ade54a9fe6f6cf730658c053a04f4460"
    )
    assert row["dataset_archive"]["sha256"] == "NOT_YET_MEASURED"


def test_p2_35_selects_run_before_archive_inventory() -> None:
    row = _load()
    selection = row["selection_basis"]
    assert selection["source_repository_previously_used_by_breachscope"] is False
    assert selection["breachscope_repository_search_hits_for_socbed_before_binding"] == 0
    assert selection["dataset_archive_downloaded_before_binding"] is False
    assert selection["archive_member_inventory_observed_before_binding"] is False
    assert selection["windows_event_log_content_observed_before_binding"] is False
    assert selection["breachscope_detector_executed_on_source_before_binding"] is False

    selected = row["selected_run"]
    assert selected["host_configuration"] == "host1_bestpractice"
    assert selected["iteration"] == 1
    assert "winlogbeat_01.jsonl" in selected["expected_windows_member_policy"]
    assert selected["zero_or_multiple_matching_members"] == "ABORT_UNSUPPORTED"
    assert selected["fallback_to_other_configuration_or_iteration_after_inventory"] is False


def test_p2_35_freezes_source_defined_eight_step_order() -> None:
    row = _load()["source_defined_timeline"]
    assert row["session_log_window_seconds"] == 3600
    assert row["first_attack_nominal_offset_seconds"] == 900
    assert row["inter_step_nominal_spacing_seconds"] == 180
    expected = [
        ("misc_sqlmap", 900),
        ("infect_email_exe", 1080),
        ("c2_take_screenshot", 1260),
        ("c2_exfiltration", 1440),
        ("c2_mimikatz", 1620),
        ("misc_download_malware", 1800),
        ("misc_set_autostart", 1980),
        ("misc_execute_malware", 2160),
    ]
    assert [(x["attack"], x["nominal_offset_seconds"]) for x in row["steps"]] == expected


def test_p2_35_protocol_prevents_peeking_and_result_driven_reruns() -> None:
    row = _load()["protocol"]
    assert row["binding_must_merge_before_dataset_download"] is True
    assert row["phase_a_binding_only"] is True
    assert row["duplicate_canonical_measurement_allowed"] is False
    assert row["first_completed_or_failed_execution_is_canonical"] is True
    assert row["result_driven_remeasurement_allowed"] is False
    assert row["tuning_after_source_observation_before_measurement_allowed"] is False
    phase_b = "\n".join(row["phase_b_after_binding_merge"])
    assert "member names and uncompressed sizes only" in phase_b
    assert "do not read selected Windows JSONL content" in phase_b
    assert "do not execute BreachScope" in phase_b


def test_p2_35_claims_remain_fail_closed() -> None:
    claim = _load()["claim_boundary"]
    assert claim["independent_source"] is True
    assert claim["source_timeline_known_before_event_observation"] is True
    assert claim["timeline_reconstruction_quality"] == "NOT_YET_MEASURED"
    assert claim["chain_precision"] == "NOT_CLAIMED"
    assert claim["chain_recall"] == "NOT_CLAIMED"
    assert claim["scenario_precision"] == "NOT_CLAIMED"
    assert claim["scenario_recall"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
