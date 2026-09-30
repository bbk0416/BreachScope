from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "external_baseline"
    / "p2_36b_current_rulepack_fresh_source_revalidation_contract.yaml"
)
RUNNER = (
    ROOT
    / "scripts"
    / "p2_36b_current_rulepack_fresh_source_revalidation.py"
)


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _load_runner():
    spec = importlib.util.spec_from_file_location("p2_36b_runner_contract", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p2_36b_execution_identity_and_preregistration() -> None:
    row = _load()
    assert row["analysis_id"] == (
        "p2-36b-current-rulepack-fresh-source-revalidation-v1"
    )
    assert row["status"] == "PREREGISTERED_EXECUTION_NOT_RUN"
    assert row["predecessor"]["same_analysis_id_retry_forbidden"] is True
    assert row["predecessor"]["predecessor_sources_reused"] is False
    prereg = row["source_preregistration"]
    assert prereg["merge_commit"] == (
        "21bca78b1a0ed649480bb78b8ee437d053bdeaf2"
    )
    assert prereg["sha256"] == (
        "b2870d5a367c5edd80597bb69d6d020556bae948170a0c67b266d56d790f3524"
    )
    assert prereg["merged_before_exact_byte_binding"] is True


def test_p2_36b_freezes_same_73_rule_product() -> None:
    frozen = _load()["frozen_product"]
    assert frozen["repo_commit"] == (
        "a469378c0b26bb25ab005ecf2edd681a0b126713"
    )
    assert frozen["rules_tree_sha256"] == (
        "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
    )
    assert frozen["rule_count"] == 73
    assert frozen["rule_file_count"] == 5
    assert frozen["execution_mode"] == "SEPARATE_FROZEN_GIT_WORKTREE"
    assert frozen["product_changed_from_p2_36"] is False


def test_p2_36b_runner_hash_and_lock_are_frozen() -> None:
    runner = _load()["runner"]
    digest = hashlib.sha256(
        RUNNER.read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert digest == runner["sha256"]
    assert digest == (
        "d31372ea9bf88a21322d59a8a65d3ac5650768e5c1f4ee1edc44df1273f2c77a"
    )
    assert runner["one_canonical_execution_only"] is True
    assert runner["same_analysis_id_retry_allowed"] is False
    assert runner["permanent_global_lock"] == (
        "P2_36B_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
    )
    assert runner["zero_parsed_event_benign_member_policy"] == (
        "RECORD_EMPTY_AND_CONTINUE"
    )
    assert runner["zero_parsed_event_attack_fixture_policy"] == "FAIL_FIXTURE"


def test_p2_36b_attack_exact_bytes_are_frozen() -> None:
    attack = _load()["attack_revalidation"]
    source = attack["source"]
    assert source["pinned_commit"] == (
        "24d78c6401672c8a1d690e660e351c51f528414f"
    )
    assert source["readme_git_blob_sha1"] == (
        "06ed0710874b506ae2ccc178717ad30ca380edfe"
    )
    assert source["readme_sha256"] == (
        "f61d914301fc5be76da860d6f67b0b40e7c49fcbaf371e710cdb6c04ac35be9e"
    )
    rows = attack["datasets"]
    assert len(rows) == 1
    assert rows[0]["source_path"] == (
        "Amadey - 9c9aa5 Campaign/9c9aa5_campaign.evtx"
    )
    assert rows[0]["size_bytes"] == 3_215_360
    assert rows[0]["git_blob_sha1"] == (
        "6a9ae012734b9fe86a5fcf5a804f69e13170ab8c"
    )
    assert rows[0]["sha256"] == (
        "4bd7b8d516e439faa837b40331a839449484c150a697a365270b169dd2179bb7"
    )
    assert attack["selection_policy"]["single_fixture_source_limitation"] is True


def test_p2_36b_benign_archive_and_inventory_are_frozen() -> None:
    benign = _load()["benign_revalidation"]
    assert benign["archive"] == {
        "asset_name": "win11-client.tgz",
        "size_bytes": 133_144_670,
        "sha256": (
            "6caab8391ac3cf7135e2fd5f545c7b116a2b445ec061f83d05873f8081ff0202"
        ),
    }
    inventory = benign["inventory"]
    assert inventory["evtx_member_count"] == 355
    assert inventory["total_evtx_bytes"] == 1_813_389_312
    assert inventory["inventory_sha256"] == (
        "94c82df7f55122212661f02004c475f64bef715705b398dcf221ca4affb3433c"
    )
    assert inventory["inventory_uses_names_and_sizes_only"] is True
    assert inventory["event_contents_parsed_while_binding_inventory"] is False
    assert inventory["post_inventory_member_dropping_allowed"] is False


def test_p2_36b_empty_benign_member_is_nonfatal_but_attack_empty_is_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_runner()

    def empty_iter(path, parser, Event, stats):
        if False:
            yield None

    monkeypatch.setattr(module, "iter_evtx_events", empty_iter)

    def no_findings(events, rules):
        for _ in events:
            pass
        return iter(())

    metrics = module.score_evtx(
        Path("synthetic-empty.evtx"),
        no_findings,
        None,
        None,
        [],
        allow_empty=True,
    )
    assert metrics["empty"] is True
    assert metrics["parsed_events"] == 0
    assert metrics["findings"] == 0

    with pytest.raises(RuntimeError, match="parsed zero events"):
        module.score_evtx(
            Path("synthetic-empty.evtx"),
            no_findings,
            None,
            None,
            [],
            allow_empty=False,
        )


def test_p2_36b_runner_records_empty_members_and_keeps_archive_guard() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert 'member_status = "EMPTY" if metrics["empty"] else "COMPLETED"' in source
    assert "empty_members += 1" in source
    assert '"empty_member_count": empty_members' in source
    assert '"nonempty_member_count": len(inventory) - empty_members' in source
    assert 'raise RuntimeError("benign archive parsed zero events")' in source


def test_p2_36b_protocol_and_claim_boundary_are_narrow() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["execution_contract_must_be_merged_before_detector_run"] is True
    assert protocol["result_acceptance_depends_on_measurement_value"] is False
    assert protocol["empty_benign_member_is_not_a_detector_failure"] is True
    assert protocol["entire_benign_archive_zero_events_is_failure"] is True

    claim = row["claim_boundary"]
    assert claim["attack_source_family_previously_used_by_breachscope"] is False
    assert claim["benign_source_family_previously_used_by_breachscope"] is True
    assert claim["attack_source_contains_single_selected_fixture"] is True
    assert claim["combined_independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_fraction_is_event_level_recall"] is False
    assert claim["benign_flagged_events_are_confirmed_false_positives"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36b_execution_not_started() -> None:
    assert _load()["execution_state"] == {
        "canonical_execution_started": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }
