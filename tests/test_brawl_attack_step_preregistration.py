import hashlib
from pathlib import Path

import yaml

from breachscope.brawl_score import (
    EXACT_TIME_TOLERANCE_SECONDS,
    LEGACY_ATTACK_CROSSWALK,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "brawl_attack_step_scoring_preregistration.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_brawl_attack_step_preregistration_freezes_source_adapter_and_scorer():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    assert contract["schema"] == "breachscope.brawl_attack_step_scoring_preregistration.v2"
    assert contract["analysis_id"] == "brawl-independent-attack-step-technique-holdout-v1"
    assert contract["status"] == "PREREGISTERED_NOT_RUN"

    source = contract["source"]
    assert source["repository"] == "mitre/brawl-public-game-001"
    assert source["commit"] == "7ec51fac8fc05ea01da210f604b821ef52818173"
    assert source["archive_git_blob_sha1"] == "257a4ed9dcba427f75cc11da286f44004ed6c7c0"
    assert source["archive_size_bytes"] == 4967769
    assert source["raw_archive_downloaded_before_preregistration"] is False
    assert source["raw_archive_contents_inspected_before_preregistration"] is False

    adapter = contract["adapter"]
    scorer = contract["scorer"]
    evaluator = contract["evaluator"]
    assert _sha256(ROOT / adapter["path"]) == adapter["sha256"]
    assert _sha256(ROOT / scorer["path"]) == scorer["sha256"]
    assert _sha256(ROOT / evaluator["path"]) == evaluator["sha256"]
    assert _sha256(ROOT / adapter["contract"]) == adapter["contract_sha256"]
    assert adapter["raw_data_used_for_implementation"] is False
    assert scorer["raw_data_used_for_implementation"] is False
    assert evaluator["raw_data_used_for_implementation"] is False
    assert evaluator["source_download_capability"] is False
    assert "BRAWL_ATTACK_STEP_TECHNIQUE_HOLDOUT_V1.lock" in evaluator["permanent_lock"]
    assert adapter["sysmon_timestamp_policy"]["primary"] == "data_model.fields.utc_time"
    assert adapter["sysmon_timestamp_policy"]["fallback"] == "@timestamp"


def test_brawl_attack_step_preregistration_crosswalk_matches_code():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    assert contract["attack_id_crosswalk"]["mapping"] == LEGACY_ATTACK_CROSSWALK
    assert contract["time_matching"]["exact_time"]["tolerance_seconds_before"] == EXACT_TIME_TOLERANCE_SECONDS
    assert contract["time_matching"]["exact_time"]["tolerance_seconds_after"] == EXACT_TIME_TOLERANCE_SECONDS


def test_brawl_attack_step_preregistration_uses_pair_denominator():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    scope = contract["scope"]
    assert scope["primary_unit"] == "BSF step x unique upstream ATT&CK technique pair"
    assert scope["primary_metric"] == "brawl_attack_step_technique_hit_fraction"
    assert any("every unique" in item for item in scope["pair_selection_rule"])
    assert any("no post-hoc" in item for item in scope["pair_selection_rule"])

    aggregation = contract["aggregation"]
    assert "total_step_technique_pairs" in aggregation["report_counts"]
    assert "pair_hits" in aggregation["report_counts"]
    assert "pair_misses" in aggregation["report_counts"]
    assert "pair_errors" in aggregation["report_counts"]
    assert "step_technique_hit_fraction_of_all_pairs" in aggregation["report_fractions"]
    assert "step_technique_hit_fraction_of_evaluable_pairs" in aggregation["report_fractions"]


def test_brawl_attack_step_preregistration_couples_host_and_time_per_event():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    time_matching = contract["time_matching"]
    assert "same referenced BSF event" in time_matching["anti_cross_join_rule"]
    assert "never used for HIT matching" in time_matching["outer_step_window"]

    hit = contract["pair_hit_semantics"]["HIT"]
    assert any("same Finding host" in item for item in hit)
    assert any("same Finding timestamp" in item for item in hit)


def test_brawl_attack_step_preregistration_is_one_pass_and_not_recall():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    gate = contract["execution_gate"]
    assert gate["retry_allowed"] is False
    assert gate["canonical_execution_count"] == 1
    assert any("no detector or rule changes" in item for item in gate["after_raw_inspection"])
    assert any("no adapter or scorer changes" in item for item in gate["after_raw_inspection"])
    assert any("no ATT&CK crosswalk" in item for item in gate["after_raw_inspection"])

    scope = contract["scope"]
    assert "event-level recall" in scope["excluded_claims"]

    claims = contract["claim_boundaries"]
    assert claims["event_level_attack_ground_truth"] == "NOT_AVAILABLE"
    assert claims["event_level_benign_ground_truth"] == "NOT_AVAILABLE"
    assert claims["step_level_red_bot_attack_oracle"] == "AVAILABLE"
    assert claims["step_technique_pair_oracle"] == "AVAILABLE"
    assert claims["production_accuracy"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"


def test_brawl_attack_step_preregistration_errors_are_not_misses():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    semantics = contract["pair_hit_semantics"]
    assert semantics["error_policy"] == "ERROR is never converted to MISS"
    assert any("upstream ATT&CK id absent" in item for item in semantics["ERROR"])
    assert any("missing or invalid time" in item for item in semantics["ERROR"])

    status = contract["step_status"]
    assert "one or more pairs" in status["ERROR"]
    assert "primary metric denominator is step-technique pairs" in status["note"]