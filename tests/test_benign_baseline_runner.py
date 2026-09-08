from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_benign_baseline.py"
RECIPE = ROOT / "external_baseline" / "p2_09d_benign_sources.yaml"


def _module():
    spec = importlib.util.spec_from_file_location(
        "breachscope_run_benign_baseline", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_tar(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def test_p2_09d_recipe_is_pinned_and_valid():
    module = _module()
    recipe = module.load_recipe(RECIPE)
    source = recipe["source"]

    assert recipe["evaluation_class"] == "external_baseline"
    assert recipe["label_policy"] == "benign_by_source_intent"
    assert source["repository"] == "NextronSystems/evtx-baseline"
    assert source["release_tag"] == "v0.8.4"
    assert source["asset_id"] == 371540503
    assert source["asset_name"] == "win10-client.tgz"
    assert source["size"] == 70844052
    assert source["sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert source["license"] == "Apache-2.0"


def test_recipe_rejects_invalid_digest():
    module = _module()
    recipe = module.load_recipe(RECIPE)
    broken = json.loads(json.dumps(recipe))
    broken["source"]["sha256"] = "abc"

    with pytest.raises(module.BaselineError, match="source.sha256"):
        module.validate_recipe(broken)


def test_verify_archive_checks_size_and_sha256(tmp_path):
    module = _module()
    payload = b"benign-archive"
    archive = tmp_path / "x.tgz"
    archive.write_bytes(payload)
    source = {
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }

    verified = module.verify_archive(archive, source)
    assert verified["size"] == len(payload)
    assert verified["sha256"] == hashlib.sha256(payload).hexdigest()

    source["size"] += 1
    with pytest.raises(module.BaselineError, match="size mismatch"):
        module.verify_archive(archive, source)


def test_extract_evtx_archive_only_materializes_evtx(tmp_path):
    module = _module()
    archive = tmp_path / "good.tgz"
    _write_tar(
        archive,
        [
            ("donation/Security.evtx", b"security"),
            ("donation/System.EVTX", b"system"),
            ("donation/README.txt", b"not-an-evtx"),
        ],
    )

    rows = module.extract_evtx_archive(archive, tmp_path / "corpus")

    assert [row["path"] for row in rows] == [
        "donation/Security.evtx",
        "donation/System.EVTX",
    ]
    assert (tmp_path / "corpus" / "donation" / "Security.evtx").read_bytes() == b"security"
    assert not (tmp_path / "corpus" / "donation" / "README.txt").exists()


def test_extract_evtx_archive_rejects_path_traversal(tmp_path):
    module = _module()
    archive = tmp_path / "bad.tgz"
    _write_tar(archive, [("../escape.evtx", b"x")])

    with pytest.raises(module.BaselineError, match="unsafe archive path"):
        module.extract_evtx_archive(archive, tmp_path / "corpus")

    assert not (tmp_path / "escape.evtx").exists()


def test_build_manifest_records_benign_external_baseline():
    module = _module()
    recipe = module.load_recipe(RECIPE)
    files = [
        {
            "path": "donation/Security.evtx",
            "format": "evtx",
            "sha256": "a" * 64,
            "size": 3,
        }
    ]
    archive = {"size": recipe["source"]["size"], "sha256": recipe["source"]["sha256"]}

    manifest = module.build_evaluator_manifest(recipe, files, archive)

    assert manifest["schema"] == "breachscope.external_holdout.v1"
    assert manifest["evaluation_class"] == "external_baseline"
    assert manifest["scenarios"] == []
    assert manifest["protocol"] == {
        "independent_from_rule_authoring": True,
        "ground_truth_prepared_without_breachscope_findings": True,
        "final_holdout_seen_before_rule_freeze": True,
    }
    assert manifest["provenance"]["label_policy"] == "benign_by_source_intent"
    assert manifest["provenance"]["production_false_positive_rate_claimed"] is False
    assert manifest["provenance"]["event_level_manual_adjudication"] is False


def test_benign_labels_cover_every_index_event(tmp_path):
    module = _module()
    index_path = tmp_path / "event_index.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    keys = ["a" * 64, "b" * 64]
    with index_path.open("w", encoding="utf-8") as handle:
        for key in keys:
            handle.write(json.dumps({"event_key": key}) + "\n")

    count = module.write_benign_labels(index_path, labels_path)

    assert count == 2
    rows = [
        json.loads(line)
        for line in labels_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["event_key"] for row in rows] == keys
    assert all(row["label"] == "benign" for row in rows)
    assert all(row["expected_techniques"] == [] for row in rows)


def test_validate_only_does_not_download_or_run_detection(monkeypatch):
    module = _module()

    def forbidden(*args, **kwargs):
        raise AssertionError("validate-only must stay offline")

    monkeypatch.setattr(module, "_download", forbidden)
    monkeypatch.setattr(module, "_run", forbidden)

    assert module.main(["--validate-only"]) == 0
