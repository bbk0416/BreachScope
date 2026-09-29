from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "external_baseline"
    / "p2_36_current_rulepack_fresh_source_revalidation_contract.yaml"
)
RUNNER = ROOT / "scripts" / "p2_36_current_rulepack_fresh_source_revalidation.py"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_36_execution_identity_and_source_preregistration() -> None:
    row = _load()
    assert row["analysis_id"] == (
        "p2-36-current-rulepack-fresh-source-revalidation-v1"
    )
    assert row["status"] == "PREREGISTERED_EXECUTION_NOT_RUN"
    source = row["source_preregistration"]
    assert source["merge_commit"] == (
        "6b20cac3c3b894912eada8f3c9fff32e8dd80ace"
    )
    assert source["sha256"] == (
        "b85456b7aba3a0ee18176c3d3b7ecfab4bb933802cee12bcc5fec41b1ded236e"
    )
    assert source["merged_before_source_download_and_inventory_binding"] is True


def test_p2_36_freezes_current_73_rule_product() -> None:
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


def test_p2_36_runner_hash_and_one_shot_lock_are_fixed() -> None:
    row = _load()["runner"]
    digest = hashlib.sha256(
        RUNNER.read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert digest == row["sha256"]
    assert digest == (
        "3f94334dcd7a9363b58625ed505a92483f022274b735293eae73e9e2ddd0d063"
    )
    assert row["one_canonical_execution_only"] is True
    assert row["same_analysis_id_retry_allowed"] is False
    assert row["permanent_global_lock"] == (
        "P2_36_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
    )
    assert row["temp_free_bytes_min"] == 8 * 1024 * 1024 * 1024
    source = RUNNER.read_text(encoding="utf-8")
    body = source[source.index("def run(args: argparse.Namespace)") :]
    assert body.index("acquire_global_lock(lock)") < body.index("load_product(")
    assert body.index("acquire_global_lock(lock)") < body.index("verify_attack_repo(")
    assert body.index("acquire_global_lock(lock)") < body.index("verify_benign_archive(")


def test_p2_36_attack_exact_bytes_are_frozen() -> None:
    attack = _load()["attack_revalidation"]
    source = attack["source"]
    assert source["pinned_commit"] == (
        "d8d250d3b55779e81552adf2a5f98be1b1cfeb2f"
    )
    assert source["readme_git_blob_sha1"] == (
        "14e9fb5d59957d55c72b244a18b0a88d8d4739ad"
    )
    assert source["readme_size_bytes"] == 107
    assert source["readme_sha256"] == (
        "c68c0575c246bd04505f2fd80b8e4e7c8edd33a1455e9c073ecd802c83975f56"
    )
    rows = attack["datasets"]
    assert len(rows) == 7
    assert len({x["source_path"] for x in rows}) == 7
    assert all(len(x["git_blob_sha1"]) == 40 for x in rows)
    assert all(len(x["sha256"]) == 64 for x in rows)
    assert sum(int(x["size_bytes"]) for x in rows) == 1_536_000
    assert attack["selection_policy"]["all_selector_matches_selected"] is True
    assert (
        attack["selection_policy"]["post_execution_fixture_replacement_allowed"]
        is False
    )


def test_p2_36_benign_archive_and_inventory_are_frozen() -> None:
    benign = _load()["benign_revalidation"]
    assert benign["archive"] == {
        "asset_name": "win2022-0-20348-azure.tgz",
        "size_bytes": 143_223_928,
        "sha256": (
            "4b3337d857f8e03273f831ad25db75e02a5a8b26b5ec14bb63727459250a5a73"
        ),
    }
    inventory = benign["inventory"]
    assert inventory["evtx_member_count"] == 355
    assert inventory["total_evtx_bytes"] == 2_334_142_464
    assert inventory["inventory_sha256"] == (
        "6557bd513ba5a1b42c096eb6cde1306595d6b13f16c460aec1387548928e4666"
    )
    assert inventory["inventory_uses_names_and_sizes_only"] is True
    assert inventory["event_contents_parsed_while_binding_inventory"] is False
    assert inventory["post_inventory_member_dropping_allowed"] is False


def test_p2_36_runner_streams_and_drops_each_temp_member() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert "def iter_evtx_events(" in source
    assert "for finding in apply_rules(event_iter, rules):" in source
    assert "TemporaryDirectory(prefix=\"p2_36_benign_\")" in source
    assert "temp_path.unlink(missing_ok=True)" in source
    assert "inventory_benign_evtx_members" in source


def test_p2_36_protocol_and_claim_boundary_are_narrow() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["execution_contract_must_be_merged_before_detector_run"] is True
    assert protocol["result_acceptance_depends_on_measurement_value"] is False
    assert protocol["source_selection_must_not_change_after_observation"] is True
    assert protocol["runner_must_not_change_after_contract_merge"] is True

    claim = row["claim_boundary"]
    assert claim["attack_source_family_previously_used_by_breachscope"] is False
    assert claim["benign_source_family_previously_used_by_breachscope"] is True
    assert claim["combined_independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_fraction_is_event_level_recall"] is False
    assert claim["benign_flagged_events_are_confirmed_false_positives"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36_execution_not_started() -> None:
    assert _load()["execution_state"] == {
        "canonical_execution_started": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }
