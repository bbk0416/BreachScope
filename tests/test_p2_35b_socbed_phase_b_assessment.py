from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT = ROOT / "external_baseline" / "p2_35b_socbed_phase_b_assessment.yaml"


def _load() -> dict:
    return yaml.safe_load(ASSESSMENT.read_text(encoding="utf-8"))


def test_p2_35b_exact_archive_identity_is_bound() -> None:
    row = _load()
    assert row["status"] == "COMPLETED"
    assert row["binding_main_commit"] == "683a2207d966cb7eadb672702380bd3b0de274a9"
    archive = row["source"]["dataset_archive"]
    assert archive["expected_size_bytes"] == 77_984_817
    assert archive["actual_size_bytes"] == 77_984_817
    assert archive["expected_git_blob_sha1"] == (
        "270ea757ade54a9fe6f6cf730658c053a04f4460"
    )
    assert archive["actual_git_blob_sha1"] == archive["expected_git_blob_sha1"]
    assert archive["sha256"] == (
        "7eda65f08bbe6f274c1feff178ae132cfd0e8edbdf0a10ef08321259b6facc54"
    )
    assert archive["identity_match"] is True


def test_p2_35b_selected_member_is_unique_and_byte_frozen() -> None:
    inv = _load()["archive_inventory"]
    assert inv["member_count"] == 244
    assert inv["observation_scope"] == "MEMBER_NAMES_AND_UNCOMPRESSED_SIZES_ONLY"
    assert inv["selected_member_match_count"] == 1
    selected = inv["selected_member"]
    assert selected["path"] == "host1_bestpractice/winlogbeat_01.jsonl"
    assert selected["size_bytes"] == 21_081_975
    assert selected["sha256"] == (
        "d648be6ac0acd18a354e0e1b497800d9d41d2a511afe21308ca3c2a0b679064d"
    )
    assert selected["decoded"] is False
    assert selected["json_parsed"] is False
    assert selected["searched"] is False
    assert selected["sampled"] is False


def test_p2_35b_timing_members_are_name_only_observations() -> None:
    inv = _load()["archive_inventory"]
    assert inv["timing_anchor_member_contents_read"] is False
    assert [(x["path"], x["size_bytes"]) for x in inv["timing_anchor_candidate_members"]] == [
        ("host1_bestpractice/attackconsole_01.log", 6536),
        ("host1_bestpractice/vmconsole_01.log", 435),
        ("host1_bestpractice/attackconsole_01.stdout", 21242),
    ]


def test_p2_35b_preserves_preobservation_boundary() -> None:
    protocol = _load()["protocol"]
    assert protocol["archive_download_after_binding_merge"] is True
    assert protocol["archive_identity_verified_before_inventory"] is True
    assert protocol["selected_run_resolved_uniquely"] is True
    assert protocol["selected_member_content_observed"] is False
    assert protocol["timing_log_content_observed"] is False
    assert protocol["breachscope_detector_executed"] is False
    assert protocol["breachscope_output_observed"] is False
    assert protocol["product_or_rules_tuned_after_source_observation"] is False


def test_p2_35b_requires_phase_c_before_any_content_observation() -> None:
    nxt = _load()["next_phase"]
    assert nxt["id"] == "P2-35C"
    assert nxt["selected_member_sha256_frozen"] == (
        "d648be6ac0acd18a354e0e1b497800d9d41d2a511afe21308ca3c2a0b679064d"
    )
    assert nxt["timing_anchor_parser_required"] is True
    assert nxt["event_content_observation_before_phase_c_merge"] == "prohibited"
    assert nxt["breachscope_execution_before_phase_c_merge"] == "prohibited"


def test_p2_35b_claims_remain_unmeasured() -> None:
    claim = _load()["claim_boundary"]
    assert claim["timeline_reconstruction_quality"] == "NOT_YET_MEASURED"
    assert claim["exact_time_window_alignment"] == "NOT_YET_MEASURED"
    assert claim["attack_step_visibility"] == "NOT_YET_MEASURED"
    assert claim["chain_order_alignment"] == "NOT_YET_MEASURED"
    assert claim["scenario_order_alignment"] == "NOT_YET_MEASURED"
    assert claim["production_reconstruction_quality"] == "NOT_CLAIMED"
