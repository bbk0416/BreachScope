from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_external_baseline.py"
RECIPE = ROOT / "external_baseline" / "p2_09c_sources.yaml"


def _module():
    spec = importlib.util.spec_from_file_location(
        "breachscope_run_external_baseline", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_p2_09c_recipe_is_pinned_and_valid():
    module = _module()
    recipe = module.load_recipe(RECIPE)

    assert recipe["evaluation_class"] == "external_baseline"
    assert len(recipe["assets"]) == 10
    assert all(len(row["git_blob_sha1"]) == 40 for row in recipe["assets"])
    assert all(row["format"] == "evtx" for row in recipe["assets"])
    assert all(row["expected_techniques"] for row in recipe["assets"])


def test_git_blob_sha1_matches_git_object_contract():
    module = _module()
    data = b"hello\n"

    assert module.git_blob_sha1(data) == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_raw_github_url_quotes_spaces_but_preserves_slashes():
    module = _module()
    url = module.raw_github_url(
        "owner/repo",
        "a" * 40,
        "Credential Access/sample.evtx",
    )

    assert url.endswith("/Credential%20Access/sample.evtx")


def test_recipe_rejects_unpinned_blob():
    module = _module()
    recipe = module.load_recipe(RECIPE)
    broken = json.loads(json.dumps(recipe))
    broken["assets"][0]["git_blob_sha1"] = ""

    with pytest.raises(module.BaselineError, match="git_blob_sha1"):
        module.validate_recipe(broken)


def test_build_manifest_marks_external_baseline_not_blind():
    module = _module()
    recipe = module.load_recipe(RECIPE)
    asset = dict(recipe["assets"][0])
    payload = b"sample"
    asset["sha256"] = module._sha256_bytes(payload)
    asset["repository"] = "owner/repo"
    asset["commit"] = "b" * 40

    manifest = module.build_evaluator_manifest(recipe, [asset])

    assert manifest["schema"] == "breachscope.external_holdout.v1"
    assert manifest["evaluation_class"] == "external_baseline"
    assert manifest["protocol"] == {
        "independent_from_rule_authoring": False,
        "ground_truth_prepared_without_breachscope_findings": True,
        "final_holdout_seen_before_rule_freeze": True,
    }
    assert manifest["scenarios"][0]["expected_techniques"] == ["T1003.001"]
    assert manifest["provenance"]["final_blind_holdout"] is False


def test_ignore_labels_do_not_assert_event_ground_truth(tmp_path):
    module = _module()
    index_path = tmp_path / "index.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    keys = ["a" * 64, "b" * 64]
    with index_path.open("w", encoding="utf-8") as handle:
        for key in keys:
            handle.write(json.dumps({"event_key": key}) + "\n")

    count = module.write_ignore_labels(index_path, labels_path)

    assert count == 2
    rows = [
        json.loads(line)
        for line in labels_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["event_key"] for row in rows] == keys
    assert all(row["label"] == "ignore" for row in rows)
    assert all(row["expected_techniques"] == [] for row in rows)


def test_verify_asset_bytes_checks_git_blob_and_size():
    module = _module()
    data = b"abc"
    asset = {
        "id": "x",
        "size": 3,
        "git_blob_sha1": module.git_blob_sha1(data),
    }

    verified = module._verify_asset_bytes(asset, data)

    assert verified["size"] == 3
    assert verified["git_blob_sha1"] == module.git_blob_sha1(data)
    assert verified["sha256"] == module._sha256_bytes(data)
