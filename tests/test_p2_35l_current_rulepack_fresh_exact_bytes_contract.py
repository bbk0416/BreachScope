from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35l_current_rulepack_fresh_exact_bytes_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35l_current_rulepack_fresh_exact_bytes.py"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _runner_sha() -> str:
    return hashlib.sha256(
        RUNNER.read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()


def _module():
    spec = importlib.util.spec_from_file_location("p2_35l_contract_test", RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_p2_35l_contract_identity_and_predecessor() -> None:
    row = _load()
    assert row["schema"] == (
        "breachscope.p2_35l_current_rulepack_fresh_exact_bytes_contract.v1"
    )
    assert row["analysis_id"] == (
        "p2-35l-current-rulepack-fresh-exact-bytes-v1"
    )
    assert row["status"] == "PREREGISTERED_NOT_RUN"
    pre = row["preregistration"]
    assert pre["base_main_commit"] == (
        "078251b006a4acf124051f001ce1cb1244c0c7af"
    )
    assert pre["predecessor_result"] == (
        "external_baseline/p2_35k_current_rulepack_replay_result.yaml"
    )
    assert pre["fresh_attack_revalidation_before_p2_35l"] == "NOT_RUN"
    assert pre["fresh_benign_revalidation_before_p2_35l"] == "NOT_RUN"
    assert pre["detector_execution_on_selected_p2_35l_bytes_before_contract_merge"] is False
    assert pre["benign_archive_downloaded_before_contract_merge"] is False
    assert pre["benign_archive_inventory_before_contract_merge"] is False


def test_p2_35l_runner_and_frozen_product_are_exact() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _runner_sha()
    assert row["runner"]["sha256"] == (
        "65fb91c5313dc039c98f565577063b1555715687946b9278c8b5478d7d174e5b"
    )
    assert row["runner"]["product_repo_mode"] == (
        "SEPARATE_FROZEN_GIT_WORKTREE"
    )
    assert row["runner"]["product_python_modules_must_resolve_under_product_repo"] is True
    assert row["frozen_product"] == {
        "repo_commit": "2401f8b9b6a569b8b932451f0a0ae20ffa26abbc",
        "rules_tree_sha256": (
            "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
        ),
        "rule_count": 69,
        "rule_file_count": 5,
    }


def test_p2_35l_attack_bytes_are_prebound_and_unused() -> None:
    row = _load()["attack_revalidation"]
    assert row["source"]["repository"] == "sans-blue-team/DeepBlueCLI"
    assert row["source"]["pinned_commit"] == (
        "2eecc65698e8666408ece67525577c895676d579"
    )
    assert row["source"]["readme_git_blob_sha1"] == (
        "937616cd0cbcf5e6c5f249d9ba9f03468f65962d"
    )
    assert row["freshness"]["selected_exact_bytes_previously_detector_evaluated"] is False
    assert row["freshness"]["selected_filenames_present_in_breachscope_project_before_binding"] == 0
    assert row["freshness"]["current_p2_35i_rule_development_used_selected_exact_bytes"] is False
    assert row["freshness"]["independent_source_family"] is False

    datasets = row["datasets"]
    assert len(datasets) == 6
    assert [x["filename"] for x in datasets] == [
        "metasploit-psexec-native-target-security.evtx",
        "metasploit-psexec-native-target-system.evtx",
        "metasploit-psexec-powershell-target-system.evtx",
        "Powershell-Invoke-Obfuscation-string-menu.evtx",
        "smb-password-guessing-security.evtx",
        "powersploit-system.evtx",
    ]
    assert len({x["sha256"] for x in datasets}) == 6
    assert all(len(x["sha256"]) == 64 for x in datasets)
    assert all(len(x["git_blob_sha1"]) == 40 for x in datasets)
    assert row["measurement"]["fixture_hit_rate_is_event_level_recall"] is False


def test_p2_35l_benign_archive_is_fresh_and_source_intent_bound() -> None:
    row = _load()["benign_revalidation"]
    source = row["source"]
    assert source["repository"] == "NextronSystems/evtx-baseline"
    assert source["release_tag"] == "v0.8.4"
    assert source["release_tag_commit"] == (
        "394bd48339f84b16053ad4804b894ab00c8a6c74"
    )
    assert source["readme_git_blob_sha1"] == (
        "0e71f1bf21374b08432711db22aa50ec100f80ef"
    )
    assert "goodware evtx logs" in source["source_intent_quote"]

    fresh = row["freshness"]
    assert fresh["selected_archive_previously_detector_evaluated"] is False
    assert fresh["selected_asset_name_present_in_breachscope_project_before_binding"] == 0
    assert fresh["current_p2_35i_rule_development_used_selected_archive"] is False
    assert fresh["archive_downloaded_before_contract_merge"] is False
    assert fresh["archive_inventory_before_contract_merge"] is False
    assert fresh["event_contents_parsed_before_contract_merge"] is False
    assert fresh["independent_source_family"] is False

    archive = row["archive"]
    assert archive["asset_name"] == "win2022-evtx.tgz"
    assert archive["size_bytes"] == 27_433_731
    assert archive["sha256"] == (
        "29406757f9761b56372d40550c9bef4eb2bf82ec21ba15115910742b03c4aab2"
    )
    policy = row["member_selection_policy"]
    assert policy["selector"] == (
        "ALL_REGULAR_TAR_MEMBERS_WITH_CASE_INSENSITIVE_DOT_EVTX_SUFFIX"
    )
    assert policy["content_based_member_selection_allowed"] is False
    assert policy["post_inventory_member_dropping_allowed"] is False
    assert policy["fallback_to_different_asset_allowed"] is False
    assert row["measurement"]["flagged_events_are_confirmed_false_positives"] is False


def test_p2_35l_protocol_is_one_pass_and_value_independent() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_be_merged_before_canonical_execution"] is True
    assert protocol["one_canonical_execution_only"] is True
    assert protocol["permanent_analysis_id_global_lock"] is True
    assert protocol["global_lock_before_source_verification"] is True
    assert protocol["global_lock_before_benign_archive_inventory"] is True
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["result_acceptance_depends_on_measurement_value"] is False

    claim = row["claim_boundary"]
    assert claim["fresh_exact_bytes_for_current_69_rule_detector"] is True
    assert claim["independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_rate_is_event_level_recall"] is False
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"


def test_p2_35l_runner_acquires_lock_before_source_verification_and_inventory() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    run_body = source[source.index("def run(args: argparse.Namespace)"):]
    lock_pos = run_body.index("acquire_global_lock(lock)")
    attack_verify_pos = run_body.index("verify_attack_sources(")
    archive_verify_pos = run_body.index("verify_benign_archive(")
    benign_run_pos = run_body.index("run_benign_revalidation(")
    assert lock_pos < attack_verify_pos
    assert lock_pos < archive_verify_pos
    assert lock_pos < benign_run_pos


def test_p2_35l_load_product_resolves_code_from_supplied_repo(tmp_path: Path) -> None:
    fake = tmp_path / "product"
    (fake / "breachscope").mkdir(parents=True)
    (fake / "scripts").mkdir(parents=True)
    (fake / "breachscope" / "__init__.py").write_text("", encoding="utf-8")
    (fake / "scripts" / "__init__.py").write_text("", encoding="utf-8")
    (fake / "breachscope" / "analyzer.py").write_text(
        "def apply_rules(*args, **kwargs):\n    return []\n",
        encoding="utf-8",
    )
    (fake / "breachscope" / "ingest.py").write_text(
        "def _extract_from_xml(xml):\n    return {}\n",
        encoding="utf-8",
    )
    (fake / "breachscope" / "rules.py").write_text(
        "def load_rules(path):\n    return []\n",
        encoding="utf-8",
    )
    (fake / "breachscope" / "schemas.py").write_text(
        "class Event:\n    pass\n",
        encoding="utf-8",
    )
    (fake / "scripts" / "evaluate_external_holdout.py").write_text(
        "def rules_tree_hash(path):\n    return ('fake', 5)\n",
        encoding="utf-8",
    )
    code = f"""
import importlib.util
from pathlib import Path
runner = Path(r"{RUNNER}")
product = Path(r"{fake}")
spec = importlib.util.spec_from_file_location("p2_35l_isolated", runner)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
apply_rules, parser, load_rules, Event, tree_hash = m.load_product(product)
paths = [
    Path(apply_rules.__code__.co_filename).resolve(),
    Path(parser.__code__.co_filename).resolve(),
    Path(load_rules.__code__.co_filename).resolve(),
    Path(tree_hash.__code__.co_filename).resolve(),
]
for path in paths:
    print(path)
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    for line in completed.stdout.splitlines():
        assert Path(line).resolve().is_relative_to(fake.resolve())


def test_p2_35l_execution_state_is_not_started() -> None:
    state = _load()["execution_state"]
    assert state == {
        "canonical_execution_started": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }
