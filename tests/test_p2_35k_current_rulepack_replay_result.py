from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "p2_35k_current_rulepack_replay_result.yaml"
RAW = ROOT / "external_baseline" / "results" / "p2_35k_33f23bc" / "result.json"
LOCK = ROOT / "external_baseline" / "locks" / "P2_35K_CURRENT_RULEPACK_REPLAY.lock"
CONTRACT = ROOT / "external_baseline" / "p2_35k_current_rulepack_replay_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35k_current_rulepack_replay.py"
P25 = ROOT / "external_baseline" / "results" / "p2_25_e712fc7" / "result.json"
P26C = ROOT / "external_baseline" / "results" / "p2_26c_81b839d" / "result.json"
CURRENT = ROOT / "external_baseline" / "current_detection_evidence.yaml"
ATTRS = ROOT / ".gitattributes"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_p2_35k_canonical_artifacts_are_byte_exact() -> None:
    row = _load_yaml(SUMMARY)
    assert row["status"] == "COMPLETED"
    assert row["contract_merge_commit"] == (
        "33f23bc9a66e86c3e58faa954090ed86876d567e"
    )
    assert RAW.stat().st_size == 12_087
    assert LOCK.stat().st_size == 115
    assert _sha(RAW) == (
        "0a10eea6cc185e7f8bc15b0e75d04ec4b409da015b4a206ea4c75deec928039a"
    )
    assert _sha(LOCK) == (
        "2f6e838e3e9a8ffcb8f63ab20799303e87f9e9af97c9359c17f6a25247580cb7"
    )


def test_p2_35k_raw_result_freezes_69_rule_product_and_runner() -> None:
    raw = _load_json(RAW)
    assert raw["status"] == "completed"
    assert raw["analysis_id"] == "p2-35k-current-rulepack-postchange-replay-v1"
    assert raw["contract_sha256"] == _sha(CONTRACT)
    assert raw["runner_sha256"] == _sha(RUNNER)
    assert raw["frozen_product"] == {
        "repo_commit": "2401f8b9b6a569b8b932451f0a0ae20ffa26abbc",
        "rules_tree_sha256": (
            "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
        ),
        "rule_count": 69,
        "rule_file_count": 5,
    }


def test_p2_35k_all_replay_source_identities_match_contract() -> None:
    raw = _load_json(RAW)
    attack = raw["source_verification"]["attack"]
    benign = raw["source_verification"]["benign"]
    assert len(attack) == 8
    assert len(benign) == 5
    assert all(x["size_match"] and x["git_blob_match"] and x["sha256_match"] for x in attack)
    assert all(x["size_match"] and x["sha256_match"] for x in benign)


def test_p2_35k_attack_projection_is_unchanged_from_p2_25() -> None:
    row = _load_yaml(SUMMARY)
    assert row["attack_replay"]["summary"] == {
        "fixture_count": 8,
        "hits": 6,
        "misses": 2,
        "errors": 0,
        "fixture_hit_rate": 0.75,
    }
    assert row["attack_replay"]["aggregate_unchanged_from_p2_25"] is True
    assert row["attack_replay"]["all_fixture_status_and_finding_projections_unchanged"] is True
    assert all(
        x["status_findings_flagged_equal"]
        for x in row["attack_replay"]["per_fixture_comparison"]
    )

    historical = _load_json(P25)
    assert historical["summary"]["hits"] == 6
    assert historical["summary"]["misses"] == 2


def test_p2_35k_benign_projection_is_unchanged_from_p2_26c() -> None:
    row = _load_yaml(SUMMARY)
    current = row["benign_replay"]["summary"]
    assert current["parsed_events"] == 1_643
    assert current["parse_errors"] == 0
    assert current["findings"] == 1
    assert current["flagged_events"] == 1
    assert current["findings_by_rule"] == {"R-SCHTASK-4698": 1}
    assert current["findings_by_channel"] == {"Security": 1}
    assert current["observed_source_intent_benign_flagged_event_fraction"] == (
        1 / 1_643
    )
    assert row["benign_replay"]["projection_unchanged_from_p2_26c"] is True

    historical = _load_json(P26C)
    assert historical["measurement"]["parsed_events"] == 1_643
    assert historical["measurement"]["flagged_events"] == 1


def test_p2_35k_new_masquerading_rule_did_not_add_replay_findings() -> None:
    row = _load_yaml(SUMMARY)
    added = row["p2_35i_added_rule"]
    assert added["rule_id"] == "R-MASQUERADE-ORIGINAL-NAME-MISMATCH"
    assert added["finding_count_across_replay_sources"] == 0
    assert added["interpretation"] == "NO_ADDITIONAL_FINDING_ON_THESE_EXACT_REPLAY_BYTES"
    assert added["broader_noise_or_detection_claim_authorized"] is False


def test_p2_35k_protocol_is_first_run_only_and_p2_35j_stays_aborted() -> None:
    row = _load_yaml(SUMMARY)
    assert row["predecessor"]["p2_35j_status"] == "ABORTED_PRE_EXECUTION"
    assert row["predecessor"]["p2_35j_execution_started"] is False
    assert row["predecessor"]["p2_35j_analysis_id_reused"] is False
    protocol = row["protocol"]
    assert protocol["canonical_execution_started_exactly_once"] is True
    assert protocol["canonical_exit_code"] == 0
    assert protocol["permanent_analysis_id_global_lock_used"] is True
    assert protocol["duplicate_execution_performed"] is False
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert protocol["replace_result_for_better_outcome"] is False

    lock = _load_json(LOCK)
    assert lock["analysis_id"] == "p2-35k-current-rulepack-postchange-replay-v1"


def test_p2_35k_replay_does_not_satisfy_fresh_revalidation() -> None:
    row = _load_yaml(SUMMARY)
    decision = row["decision"]
    assert decision["replay_regression_observed_on_these_exact_projections"] is False
    assert decision["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert decision["fresh_benign_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert decision["fresh_external_validation_requirement_satisfied"] is False

    claim = row["claim_boundary"]
    assert claim["fresh_external_source"] is False
    assert claim["independent_holdout"] is False
    assert claim["fresh_current_rulepack_performance"] == "NOT_CLAIMED"
    assert claim["unchanged_replay_numbers_are_fresh_validation"] is False
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"


def test_p2_35k_historical_replay_stays_not_fresh_after_p2_35m() -> None:
    row = _load_yaml(SUMMARY)
    assert row["decision"]["fresh_attack_revalidation_after_current_rule_change"] == "NOT_RUN"
    assert row["decision"]["fresh_benign_revalidation_after_current_rule_change"] == "NOT_RUN"

    current = _load_yaml(CURRENT)
    validation = current["current_rulepack_validation"]
    assert validation["current_revalidation_id"] == "p2-35m-current-rulepack-fresh-source-revalidation"
    assert validation["fresh_attack_revalidation_after_current_rule_change"] == "COMPLETED"
    assert validation["fresh_benign_revalidation_after_current_rule_change"] == "COMPLETED"


def test_p2_35k_lock_is_configured_for_byte_exact_git_storage() -> None:
    attrs = ATTRS.read_text(encoding="utf-8")
    assert (
        "external_baseline/locks/P2_35K_CURRENT_RULEPACK_REPLAY.lock -text -whitespace"
        in attrs
    )
    assert (
        "external_baseline/results/p2_35k_33f23bc/result.json -text -eol -whitespace"
        in attrs
    )
