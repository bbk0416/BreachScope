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
    / "p2_36c_current_rulepack_fresh_source_revalidation_contract.yaml"
)
RUNNER = (
    ROOT
    / "scripts"
    / "p2_36c_current_rulepack_fresh_source_revalidation.py"
)


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _load_runner():
    spec = importlib.util.spec_from_file_location("p2_36c_runner_contract", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p2_36c_execution_identity_and_preregistration() -> None:
    row = _load()
    assert row["analysis_id"] == (
        "p2-36c-current-rulepack-fresh-source-revalidation-v1"
    )
    assert row["status"] == "PREREGISTERED_EXECUTION_NOT_RUN"
    assert row["predecessor"]["same_analysis_id_retry_forbidden"] is True
    assert row["predecessor"]["predecessor_sources_reused"] is False
    prereg = row["source_preregistration"]
    assert prereg["merge_commit"] == (
        "edd4037ccae6805b061197c469c9fd9008ec8743"
    )
    assert prereg["sha256"] == (
        "4b529725f021933a18f55f80dbe4c5ee9c91078c0ae766c164566e7bc035b0a0"
    )
    assert prereg["merged_before_exact_byte_binding"] is True


def test_p2_36c_order_normalization_changes_no_selected_bytes() -> None:
    order = _load()["source_preregistration"]["order_only_normalization"]
    assert order["source_contract_listing"] == [
        "Demo evtx Files/PtH_02.evtx",
        "Demo evtx Files/lazagneProject.evtx",
    ]
    assert order["canonical_execution_order"] == [
        "Demo evtx Files/lazagneProject.evtx",
        "Demo evtx Files/PtH_02.evtx",
    ]
    assert order["selected_path_blob_set_changed"] is False
    assert order["detector_output_observed_before_normalization"] is False


def test_p2_36c_freezes_same_73_rule_product() -> None:
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


def test_p2_36c_runner_hash_and_lock_are_frozen() -> None:
    runner = _load()["runner"]
    digest = hashlib.sha256(
        RUNNER.read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert digest == runner["sha256"]
    assert digest == (
        "568db0010108f0b012f72b75b0f629b53f910c19a9a842af4b22d5dc18ffb797"
    )
    assert runner["one_canonical_execution_only"] is True
    assert runner["same_analysis_id_retry_allowed"] is False
    assert runner["permanent_global_lock"] == (
        "P2_36C_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
    )
    assert runner["zero_parsed_event_benign_member_policy"] == (
        "RECORD_EMPTY_AND_CONTINUE"
    )


def test_p2_36c_attack_exact_bytes_are_frozen_in_canonical_order() -> None:
    attack = _load()["attack_revalidation"]
    source = attack["source"]
    assert source["pinned_commit"] == (
        "74fc950130d63141e50ad4975fd9045dbcfb7825"
    )
    assert source["readme_git_blob_sha1"] == (
        "20f520066fd5fbd236e01b3ee7eec66451e1e53d"
    )
    assert source["readme_sha256"] == (
        "87930a474e334fae5ec6ecb3b6ca396c9e44ce8c376d5b0ef5fc1b33c48b849f"
    )
    rows = attack["datasets"]
    assert [row["source_path"] for row in rows] == [
        "Demo evtx Files/lazagneProject.evtx",
        "Demo evtx Files/PtH_02.evtx",
    ]
    assert [row["sha256"] for row in rows] == [
        "a528bec6d64b47cd5d7743cb3b4ee6dc152aeb7d235834ce4c18215f178fd82e",
        "cbbfb5a70d68c0c9c5f4329438784364f0a73c260425ce452bb7af4cad22459f",
    ]
    assert attack["selection_policy"]["selected_fixture_count"] == 2
    assert attack["selection_policy"]["all_selector_matches_selected"] is True


def test_p2_36c_benign_archive_inventory_and_size_gate_are_frozen() -> None:
    benign = _load()["benign_revalidation"]
    assert benign["archive"] == {
        "asset_name": "win7-x86.tgz",
        "size_bytes": 11_109_250,
        "sha256": (
            "e755f3cd48f8a3dc8877c46622339cd44fa0929981fcfd79ada63c2bafb62b9f"
        ),
    }
    inventory = benign["inventory"]
    assert inventory["evtx_member_count"] == 129
    assert inventory["total_evtx_bytes"] == 145_166_336
    assert inventory["inventory_sha256"] == (
        "32cc564c6873c8800958c30677d7afdb5d2cc512fbc76de7f0c913d7bfe5e1d6"
    )
    assert inventory["maximum_member_name"] == (
        "win7-x86/Microsoft-Windows-Sysmon%4Operational.evtx"
    )
    assert inventory["maximum_member_size_bytes"] == 129_044_480

    gate = benign["metadata_size_gate"]
    assert gate["maximum_selected_evtx_member_size_bytes"] == 128 * 1024 * 1024
    assert gate["maximum_observed_selected_member_size_bytes"] == 129_044_480
    assert gate["passed"] is True
    assert gate["oversize_member_may_not_be_dropped"] is True
    assert gate["detector_output_observed_before_gate"] is False


def test_p2_36c_runner_enforces_size_gate_and_empty_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_runner()
    source = RUNNER.read_text(encoding="utf-8")
    assert "benign EVTX member exceeds preregistered size gate" in source
    assert "benign maximum-member size mismatch" in source
    assert 'member_status = "EMPTY" if metrics["empty"] else "COMPLETED"' in source
    assert 'raise RuntimeError("benign archive parsed zero events")' in source

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
    with pytest.raises(RuntimeError, match="parsed zero events"):
        module.score_evtx(
            Path("synthetic-empty.evtx"),
            no_findings,
            None,
            None,
            [],
            allow_empty=False,
        )


def test_p2_36c_protocol_and_claim_boundary_are_narrow() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["execution_contract_must_be_merged_before_detector_run"] is True
    assert protocol["result_acceptance_depends_on_measurement_value"] is False
    assert protocol["benign_member_size_gate_must_pass_before_scoring"] is True
    assert protocol["empty_benign_member_is_not_a_detector_failure"] is True

    claim = row["claim_boundary"]
    assert claim["attack_repository_previously_used_by_breachscope"] is False
    assert claim["attack_author_overlap_with_prior_candidate"] is True
    assert claim["benign_source_family_previously_used_by_breachscope"] is True
    assert claim["combined_independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_fraction_is_event_level_recall"] is False
    assert claim["benign_flagged_events_are_confirmed_false_positives"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36c_execution_not_started() -> None:
    assert _load()["execution_state"] == {
        "canonical_execution_started": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }
