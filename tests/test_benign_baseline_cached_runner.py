from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_benign_baseline_cached.py"
RECIPE = ROOT / "external_baseline" / "p2_09d_benign_sources.yaml"


def _module():
    spec = importlib.util.spec_from_file_location(
        "breachscope_run_benign_baseline_cached", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_cached_validate_only_stays_offline(monkeypatch):
    module = _module()

    def forbidden(*args, **kwargs):
        raise AssertionError("validate-only must not run network or detection")

    monkeypatch.setattr(module.base, "materialize_archive", forbidden)
    monkeypatch.setattr(module, "_run", forbidden)

    assert module.main(["--validate-only"]) == 0


def test_jsonl_manifest_preserves_external_baseline_contract():
    module = _module()
    recipe = module.base.load_recipe(RECIPE)
    archive = {
        "size": recipe["source"]["size"],
        "sha256": recipe["source"]["sha256"],
    }
    files = [
        {
            "path": "donation/Security.jsonl",
            "format": "jsonl",
            "sha256": "a" * 64,
            "source_evtx_path": "donation/Security.evtx",
            "source_evtx_sha256": "b" * 64,
            "size": 10,
        }
    ]

    manifest = module.build_jsonl_manifest(recipe, files, archive)

    assert manifest["schema"] == "breachscope.external_holdout.v1"
    assert manifest["evaluation_class"] == "external_baseline"
    assert manifest["scenarios"] == []
    assert manifest["files"] == [
        {
            "path": "donation/Security.jsonl",
            "format": "jsonl",
            "sha256": "a" * 64,
        }
    ]
    assert manifest["provenance"]["label_policy"] == "benign_by_source_intent"
    assert manifest["provenance"]["materialization"] == (
        "evtx_to_jsonl_once_before_index_and_score"
    )
    assert manifest["provenance"]["production_false_positive_rate_claimed"] is False


def test_materialize_jsonl_once_converts_each_evtx_exactly_once(tmp_path, monkeypatch):
    module = _module()
    evtx_root = tmp_path / "evtx"
    jsonl_root = tmp_path / "jsonl"
    (evtx_root / "a").mkdir(parents=True)
    (evtx_root / "b").mkdir(parents=True)
    (evtx_root / "a" / "Security.evtx").write_bytes(b"security")
    (evtx_root / "b" / "System.evtx").write_bytes(b"system")

    calls: list[str] = []
    outputs: list[Path] = []

    def fake_convert(input_dir: Path):
        source = next(Path(input_dir).glob("*.evtx"))
        calls.append(source.name)
        out = Path(tempfile.mkdtemp(prefix="p2-09d-test-convert-"))
        outputs.append(out)
        (out / f"{source.stem}.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "host": "HOST",
                    "source": "WindowsEventLog",
                    "event_id": "1",
                    "record_id": len(calls),
                    "channel": source.stem,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return out

    import breachscope.ingest as ingest

    monkeypatch.setattr(ingest, "convert_evtx_dir", fake_convert)

    rows = module.materialize_jsonl_once(
        [
            {
                "path": "a/Security.evtx",
                "sha256": "1" * 64,
                "size": 8,
            },
            {
                "path": "b/System.evtx",
                "sha256": "2" * 64,
                "size": 6,
            },
        ],
        evtx_root,
        jsonl_root,
    )

    assert calls == ["Security.evtx", "System.evtx"]
    assert [row["path"] for row in rows] == [
        "a/Security.jsonl",
        "b/System.jsonl",
    ]
    assert all(row["format"] == "jsonl" for row in rows)
    assert (jsonl_root / "a" / "Security.jsonl").is_file()
    assert (jsonl_root / "b" / "System.jsonl").is_file()
    assert all(not path.exists() for path in outputs)


def test_materialize_jsonl_once_rejects_unsafe_path(tmp_path):
    module = _module()
    with pytest.raises(module.base.BaselineError, match="unsafe corpus path"):
        module.materialize_jsonl_once(
            [{"path": "../escape.evtx", "sha256": "1" * 64, "size": 1}],
            tmp_path,
            tmp_path / "jsonl",
        )


def test_summary_adapter_uses_evaluator_ignored_events_contract(tmp_path, monkeypatch):
    module = _module()
    recipe = module.base.load_recipe(RECIPE)
    archive = {
        "size": recipe["source"]["size"],
        "sha256": recipe["source"]["sha256"],
    }
    result = {
        "corpus": {"ignored_events": 0},
    }

    captured = {}

    def fake_summary(result_arg, recipe_arg, archive_arg, extracted_arg, out_arg):
        captured["ignore"] = result_arg["corpus"]["ignore"]
        payload = {
            "schema": "test",
            "primary_metrics": {},
            "corpus": {},
        }
        (Path(out_arg) / "summary.json").parent.mkdir(parents=True, exist_ok=True)
        return payload

    monkeypatch.setattr(module.base, "_write_summary", fake_summary)

    summary = module._write_summary_fixed(
        result,
        recipe,
        archive,
        [{"path": "a.evtx"}],
        [{"path": "a.jsonl"}],
        tmp_path,
    )

    assert captured["ignore"] == 0
    assert summary["materialization"]["source_evtx_files"] == 1
    assert summary["materialization"]["materialized_jsonl_files"] == 1
