from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ABORT = ROOT / "external_baseline" / "p2_35j_current_rulepack_replay_abort.yaml"
CONTRACT = ROOT / "external_baseline" / "p2_35k_current_rulepack_replay_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35k_current_rulepack_replay.py"


def _text_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35k_runner", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p2_35j_is_sealed_as_preexecution_abort() -> None:
    row = yaml.safe_load(ABORT.read_text(encoding="utf-8"))
    assert row["status"] == "ABORTED_PRE_EXECUTION"
    assert row["reason"] == "RUNNER_PRODUCT_REPO_COMMIT_BINDING_UNUSABLE_AFTER_PREREG_MERGE"
    execution = row["execution"]
    assert execution["canonical_execution_started"] is False
    assert execution["global_lock_created"] is False
    assert execution["output_created"] is False
    assert execution["source_records_parsed"] is False
    assert execution["detector_executed"] is False
    assert row["protocol"]["same_analysis_id_reuse_allowed"] is False
    assert row["next_step"]["id"] == "P2-35K"


def test_p2_35k_freezes_same_current_detector() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-35k-current-rulepack-postchange-replay-v1"
    frozen = row["frozen_product"]
    assert frozen["repo_commit"] == "2401f8b9b6a569b8b932451f0a0ae20ffa26abbc"
    assert frozen["rules_tree_sha256"] == (
        "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    )
    assert frozen["rule_count"] == 69
    assert frozen["rule_file_count"] == 5


def test_p2_35k_runner_is_byte_frozen_and_accepts_separate_product_repo() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _text_sha(RUNNER)
    assert row["runner"]["sha256"] == (
        "ebaa30dcce665e0efc6ba52bcaeeda37de9aba2d245ca227fc11040fcc69e35d"
    )
    assert row["runner"]["product_repo_argument"] == "--product-repo"
    assert row["runner"]["product_repo_mode"] == "SEPARATE_FROZEN_GIT_WORKTREE"
    assert row["runner"]["product_python_modules_must_resolve_under_product_repo"] is True
    module = _module()
    assert module.ANALYSIS_ID == row["analysis_id"]
    assert module.global_lock_path().name == "P2_35K_CURRENT_RULEPACK_REPLAY.lock"


def test_p2_35k_preserves_exact_replay_source_identities() -> None:
    row = _load()
    attack = row["attack_replay"]
    benign = row["benign_replay"]
    assert attack["fresh_external_source"] is False
    assert len(attack["datasets"]) == 8
    assert attack["pinned_commit"] == "2eecc65698e8666408ece67525577c895676d579"
    assert benign["fresh_external_source"] is False
    assert benign["workflow_run_id"] == 35492508210
    assert benign["artifact_id"] == 10599666432
    assert len([x for x in benign["files"] if x["available"]]) == 5


def test_p2_35k_protocol_fixes_only_product_repo_separation() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["product_repo_must_be_separate_frozen_worktree"] is True
    assert protocol["product_repo_head_must_equal_frozen_product_repo_commit"] is True
    assert protocol["p2_35j_analysis_id_must_not_be_reused"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["replay_result_can_satisfy_fresh_external_validation_requirement"] is False


def test_p2_35k_claim_boundary_remains_replay_only() -> None:
    claim = _load()["claim_boundary"]
    assert claim["fresh_external_source"] is False
    assert claim["independent_holdout"] is False
    assert claim["fresh_current_rulepack_performance"] == "NOT_CLAIMED"
    assert claim["event_level_precision"] == "NOT_EVALUATED"
    assert claim["event_level_recall"] == "NOT_EVALUATED"
    assert claim["attack_level_recall"] == "NOT_EVALUATED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"


def test_p2_35k_load_product_resolves_code_from_supplied_repo(tmp_path: Path) -> None:
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
spec = importlib.util.spec_from_file_location("p2_35k_isolated", runner)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
apply_rules, parser, load_rules, Event, tree_hash = m.load_product(product)
paths = [
    Path(apply_rules.__code__.co_filename).resolve(),
    Path(parser.__code__.co_filename).resolve(),
    Path(load_rules.__code__.co_filename).resolve(),
    Path(Event.__module__.replace(".", "/")),
    Path(tree_hash.__code__.co_filename).resolve(),
]
print(paths[0])
print(paths[1])
print(paths[2])
print(paths[4])
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
