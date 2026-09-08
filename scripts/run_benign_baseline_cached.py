#!/usr/bin/env python3
"""Run P2-09D by converting each EVTX to JSONL exactly once before scoring."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import run_benign_baseline as base

ROOT = base.ROOT
EVALUATOR = base.EVALUATOR
DEFAULT_RECIPE = base.DEFAULT_RECIPE
DEFAULT_OUT = base.DEFAULT_OUT


def _log(message: str) -> None:
    print(message, flush=True)


def _run(command: list[str]) -> None:
    _log("[run] " + " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def _safe_rel(root: Path, rel_text: str) -> Path:
    rel = Path(rel_text)
    if rel.is_absolute() or ".." in rel.parts:
        raise base.BaselineError(f"unsafe corpus path: {rel_text}")
    root_resolved = root.resolve()
    target = (root_resolved / rel).resolve()
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise base.BaselineError(f"corpus path escapes root: {rel_text}") from exc
    return target


def materialize_jsonl_once(
    evtx_files: list[dict[str, Any]],
    evtx_root: Path,
    jsonl_root: Path,
) -> list[dict[str, Any]]:
    """Convert each extracted EVTX once and persist normalized JSONL for index+score."""
    from breachscope.ingest import convert_evtx_dir

    jsonl_root.mkdir(parents=True, exist_ok=True)
    materialized: list[dict[str, Any]] = []
    total = len(evtx_files)
    started = time.perf_counter()

    for index, row in enumerate(evtx_files, 1):
        rel_text = str(row["path"])
        source = _safe_rel(evtx_root, rel_text)
        if not source.is_file():
            raise base.BaselineError(f"extracted EVTX not found: {rel_text}")

        work = Path(tempfile.mkdtemp(prefix="breachscope-p2-09d-materialize-"))
        converted_dir: Path | None = None
        try:
            input_dir = work / "input"
            input_dir.mkdir()
            local = input_dir / source.name
            try:
                os.link(source, local)
            except OSError:
                shutil.copy2(source, local)

            converted = convert_evtx_dir(input_dir)
            if converted is None:
                raise base.BaselineError(f"EVTX conversion returned no output: {rel_text}")
            converted_dir = Path(converted)
            outputs = sorted(converted_dir.rglob("*.jsonl"))
            if len(outputs) != 1:
                raise base.BaselineError(
                    f"expected exactly one JSONL for {rel_text}, got {len(outputs)}"
                )

            rel_jsonl = Path(rel_text).with_suffix(".jsonl")
            target = _safe_rel(jsonl_root, rel_jsonl.as_posix())
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(outputs[0], target)

            materialized.append(
                {
                    "path": rel_jsonl.as_posix(),
                    "format": "jsonl",
                    "sha256": base._sha256_path(target),
                    "source_evtx_path": rel_text,
                    "source_evtx_sha256": str(row["sha256"]),
                    "size": target.stat().st_size,
                }
            )
        finally:
            shutil.rmtree(work, ignore_errors=True)
            if converted_dir is not None:
                shutil.rmtree(converted_dir, ignore_errors=True)

        if index == 1 or index % 25 == 0 or index == total:
            elapsed = time.perf_counter() - started
            _log(f"[materialize] {index}/{total} EVTX -> JSONL ({elapsed:.1f}s)")

    if not materialized:
        raise base.BaselineError("zero JSONL files were materialized")
    materialized.sort(key=lambda row: str(row["path"]))
    return materialized


def build_jsonl_manifest(
    recipe: dict[str, Any],
    jsonl_files: list[dict[str, Any]],
    archive_verification: dict[str, Any],
) -> dict[str, Any]:
    source = recipe["source"]
    return {
        "schema": base.EVALUATOR_SCHEMA,
        "kind": "external_blind_holdout",
        "evaluation_class": "external_baseline",
        "protocol": {
            "independent_from_rule_authoring": True,
            "ground_truth_prepared_without_breachscope_findings": True,
            "final_holdout_seen_before_rule_freeze": True,
        },
        "files": [
            {
                "path": row["path"],
                "format": "jsonl",
                "sha256": row["sha256"],
            }
            for row in jsonl_files
        ],
        "scenarios": [],
        "provenance": {
            "baseline_id": recipe["baseline_id"],
            "label_policy": recipe["label_policy"],
            "repository": source["repository"],
            "release_tag": source["release_tag"],
            "release_id": source["release_id"],
            "asset_id": source["asset_id"],
            "asset_name": source["asset_name"],
            "asset_url": source["asset_url"],
            "asset_size": archive_verification["size"],
            "asset_sha256": archive_verification["sha256"],
            "license": source["license"],
            "provenance_note": source["provenance_note"],
            "materialization": "evtx_to_jsonl_once_before_index_and_score",
            "production_false_positive_rate_claimed": False,
            "event_level_manual_adjudication": False,
        },
    }


def _write_summary_fixed(
    result: dict[str, Any],
    recipe: dict[str, Any],
    archive_verification: dict[str, Any],
    extracted_files: list[dict[str, Any]],
    jsonl_files: list[dict[str, Any]],
    out_dir: Path,
) -> dict[str, Any]:
    # The original P2-09D helper used corpus["ignore"], while the evaluator
    # contract exposes corpus["ignored_events"]. Validate the real contract here.
    corpus = result["corpus"]
    if int(corpus.get("ignored_events", -1)) != 0:
        raise base.BaselineError("benign baseline unexpectedly contains ignored events")

    compat = json.loads(json.dumps(result))
    compat["corpus"]["ignore"] = int(corpus["ignored_events"])
    summary = base._write_summary(
        compat,
        recipe,
        archive_verification,
        extracted_files,
        out_dir,
    )
    summary["materialization"] = {
        "strategy": "evtx_to_jsonl_once_before_index_and_score",
        "source_evtx_files": len(extracted_files),
        "materialized_jsonl_files": len(jsonl_files),
        "reason": "Avoid duplicate expensive EVTX parsing in evaluator index and score passes.",
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )
    return summary


def run_baseline(args: argparse.Namespace) -> int:
    recipe_path = Path(args.recipe).resolve()
    recipe = base.load_recipe(recipe_path)

    if args.validate_only:
        source = recipe["source"]
        _log(
            "P2-09D cached source recipe: PASS "
            f"({source['repository']} {source['release_tag']} / {source['asset_name']})"
        )
        _log("Network access: NOT USED")
        _log("Detection rules executed: NO")
        return 0

    out_dir = Path(args.out).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    raw_root = out_dir / "raw"
    evtx_root = out_dir / "corpus_evtx"
    jsonl_root = out_dir / "corpus_jsonl"
    freeze_path = out_dir / "rules_freeze.json"
    manifest_path = out_dir / "manifest.yaml"
    index_path = out_dir / "event_index.jsonl"
    labels_path = out_dir / "labels_benign.jsonl"
    result_path = out_dir / "result.json"

    total_started = time.perf_counter()

    _run(
        [
            sys.executable,
            str(EVALUATOR),
            "freeze",
            "--repo",
            str(ROOT),
            "--rules-dir",
            str(ROOT / "rules"),
            "--out",
            str(freeze_path),
        ]
    )

    stage = time.perf_counter()
    archive_path, archive_verification = base.materialize_archive(
        recipe, raw_root, timeout=args.timeout
    )
    _log(f"[timing] download+verify {time.perf_counter() - stage:.1f}s")

    stage = time.perf_counter()
    extracted_files = base.extract_evtx_archive(archive_path, evtx_root)
    _log(
        f"[extract] {len(extracted_files)} EVTX files "
        f"({time.perf_counter() - stage:.1f}s)"
    )

    stage = time.perf_counter()
    jsonl_files = materialize_jsonl_once(extracted_files, evtx_root, jsonl_root)
    _log(
        f"[timing] EVTX materialization {time.perf_counter() - stage:.1f}s; "
        f"{len(jsonl_files)} JSONL files"
    )

    manifest = build_jsonl_manifest(recipe, jsonl_files, archive_verification)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )

    stage = time.perf_counter()
    _run(
        [
            sys.executable,
            str(EVALUATOR),
            "index",
            "--manifest",
            str(manifest_path),
            "--corpus-root",
            str(jsonl_root),
            "--out",
            str(index_path),
        ]
    )
    _log(f"[timing] index {time.perf_counter() - stage:.1f}s")

    label_count = base.write_benign_labels(index_path, labels_path)
    _log(f"[labels] {label_count} events -> benign_by_source_intent")

    stage = time.perf_counter()
    _run(
        [
            sys.executable,
            str(EVALUATOR),
            "score",
            "--repo",
            str(ROOT),
            "--manifest",
            str(manifest_path),
            "--corpus-root",
            str(jsonl_root),
            "--labels",
            str(labels_path),
            "--freeze",
            str(freeze_path),
            "--rules-dir",
            str(ROOT / "rules"),
            "--out",
            str(result_path),
        ]
    )
    _log(f"[timing] score {time.perf_counter() - stage:.1f}s")

    result = json.loads(result_path.read_text(encoding="utf-8"))
    summary = _write_summary_fixed(
        result,
        recipe,
        archive_verification,
        extracted_files,
        jsonl_files,
        out_dir,
    )
    metrics = summary["primary_metrics"]
    _log(f"[timing] total {time.perf_counter() - total_started:.1f}s")
    _log(f"P2-09D benign baseline complete: {out_dir}")
    _log(
        "False positives: "
        f"{metrics['false_positives']}/{summary['corpus']['events']} "
        f"({metrics['false_positive_rate']:.6%})"
    )
    _log("Production false-positive rate: NOT CLAIMED")
    return 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "Run BreachScope P2-09D while materializing EVTX to JSONL once "
            "before evaluator index and score passes."
        )
    )
    ap.add_argument("--recipe", default=str(DEFAULT_RECIPE))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the pinned benign source recipe without network or detection.",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run_baseline(args)
    except (
        base.BaselineError,
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        print(f"P2-09D ERROR: {exc}", file=sys.stderr, flush=True)
        return 2
    except subprocess.CalledProcessError as exc:
        print(
            f"P2-09D ERROR: subprocess failed with exit code {exc.returncode}",
            file=sys.stderr,
            flush=True,
        )
        return int(exc.returncode or 2)


if __name__ == "__main__":
    raise SystemExit(main())
