#!/usr/bin/env python3
"""Prepare and run the pinned P2-09C external attack baseline.

Raw third-party datasets are downloaded into ignored ``out/`` paths and are
never committed by this tool. The existing evaluate_external_holdout.py
remains the scoring authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RECIPE = ROOT / "external_baseline" / "p2_09c_sources.yaml"
DEFAULT_OUT = ROOT / "out" / "external_baseline" / "p2_09c"
EVALUATOR = ROOT / "scripts" / "evaluate_external_holdout.py"
RECIPE_SCHEMA = "breachscope.external_baseline_sources.v1"
MANIFEST_SCHEMA = "breachscope.external_holdout.v1"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


class BaselineError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # nosec B324: Git object identity


def raw_github_url(repository: str, commit: str, upstream_path: str) -> str:
    quoted = urllib.parse.quote(upstream_path, safe="/")
    return f"https://raw.githubusercontent.com/{repository}/{commit}/{quoted}"


def _safe_relative_path(value: str, *, field: str) -> Path:
    path = Path(value)
    if not value.strip() or path.is_absolute() or ".." in path.parts:
        raise BaselineError(f"{field} must be a safe relative path: {value!r}")
    return path


def load_recipe(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise BaselineError("source recipe must be a YAML mapping")
    validate_recipe(data)
    return data


def validate_recipe(recipe: dict[str, Any]) -> None:
    if recipe.get("schema") != RECIPE_SCHEMA:
        raise BaselineError(f"recipe schema must be {RECIPE_SCHEMA!r}")
    if recipe.get("evaluation_class") != "external_baseline":
        raise BaselineError("P2-09C recipe evaluation_class must be external_baseline")
    if not str(recipe.get("baseline_id") or "").strip():
        raise BaselineError("baseline_id is required")

    providers = recipe.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise BaselineError("providers must be a non-empty mapping")
    for provider_id, provider in providers.items():
        if not isinstance(provider, dict):
            raise BaselineError(f"provider {provider_id!r} must be a mapping")
        repository = str(provider.get("repository") or "").strip()
        commit = str(provider.get("commit") or "").strip().lower()
        if repository.count("/") != 1:
            raise BaselineError(f"provider {provider_id!r} repository must be owner/name")
        if not SHA1_RE.fullmatch(commit):
            raise BaselineError(f"provider {provider_id!r} commit must be a 40-char SHA")

    assets = recipe.get("assets")
    if not isinstance(assets, list) or not assets:
        raise BaselineError("assets must be a non-empty list")

    ids: set[str] = set()
    local_paths: set[str] = set()
    scenario_ids: set[str] = set()
    for row in assets:
        if not isinstance(row, dict):
            raise BaselineError("every asset entry must be a mapping")
        asset_id = str(row.get("id") or "").strip()
        if not asset_id or asset_id in ids:
            raise BaselineError("asset ids must be non-empty and unique")
        ids.add(asset_id)

        provider_id = str(row.get("provider") or "").strip()
        if provider_id not in providers:
            raise BaselineError(f"asset {asset_id}: unknown provider {provider_id!r}")

        upstream_path = str(row.get("upstream_path") or "")
        local_path = str(row.get("local_path") or "")
        _safe_relative_path(upstream_path, field=f"asset {asset_id} upstream_path")
        _safe_relative_path(local_path, field=f"asset {asset_id} local_path")
        if local_path in local_paths:
            raise BaselineError(f"asset {asset_id}: duplicate local_path {local_path!r}")
        local_paths.add(local_path)

        fmt = str(row.get("format") or "").strip().lower()
        if fmt not in {"evtx", "jsonl"}:
            raise BaselineError(f"asset {asset_id}: format must be evtx or jsonl")
        expected_suffix = f".{fmt}"
        if not local_path.casefold().endswith(expected_suffix):
            raise BaselineError(
                f"asset {asset_id}: local_path must end with {expected_suffix}"
            )

        blob_sha = str(row.get("git_blob_sha1") or "").strip().lower()
        if not SHA1_RE.fullmatch(blob_sha):
            raise BaselineError(f"asset {asset_id}: git_blob_sha1 must be a 40-char SHA")

        size = row.get("size")
        if not isinstance(size, int) or size <= 0:
            raise BaselineError(f"asset {asset_id}: size must be a positive integer")

        scenario_id = str(row.get("scenario_id") or "").strip()
        if not scenario_id or scenario_id in scenario_ids:
            raise BaselineError("scenario_id values must be non-empty and unique")
        scenario_ids.add(scenario_id)

        techniques = row.get("expected_techniques")
        if not isinstance(techniques, list) or not techniques:
            raise BaselineError(f"asset {asset_id}: expected_techniques is required")
        normalized = [str(item).upper() for item in techniques]
        if len(set(normalized)) != len(normalized):
            raise BaselineError(f"asset {asset_id}: expected_techniques must be unique")
        bad = [item for item in normalized if not TECHNIQUE_RE.fullmatch(item)]
        if bad:
            raise BaselineError(f"asset {asset_id}: invalid ATT&CK technique(s): {bad}")

        if not str(row.get("mapping_basis") or "").strip():
            raise BaselineError(f"asset {asset_id}: mapping_basis is required")


def select_assets(
    recipe: dict[str, Any], requested_ids: Iterable[str] | None
) -> list[dict[str, Any]]:
    assets = list(recipe["assets"])
    requested = [item for item in (requested_ids or []) if item]
    if not requested:
        return assets
    by_id = {str(row["id"]): row for row in assets}
    unknown = sorted(set(requested) - set(by_id))
    if unknown:
        raise BaselineError(f"unknown asset id(s): {unknown}")
    requested_set = set(requested)
    return [row for row in assets if str(row["id"]) in requested_set]


def _download(url: str, *, timeout: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "BreachScope-P2-09C/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _verify_asset_bytes(asset: dict[str, Any], data: bytes) -> dict[str, Any]:
    asset_id = str(asset["id"])
    expected_size = int(asset["size"])
    if len(data) != expected_size:
        raise BaselineError(
            f"{asset_id}: size mismatch expected={expected_size} actual={len(data)}"
        )
    actual_blob = git_blob_sha1(data)
    expected_blob = str(asset["git_blob_sha1"]).lower()
    if actual_blob != expected_blob:
        raise BaselineError(
            f"{asset_id}: Git blob mismatch expected={expected_blob} actual={actual_blob}"
        )
    expected_sha256 = str(asset.get("sha256") or "").strip().lower()
    actual_sha256 = _sha256_bytes(data)
    if expected_sha256 and actual_sha256 != expected_sha256:
        raise BaselineError(
            f"{asset_id}: SHA-256 mismatch expected={expected_sha256} actual={actual_sha256}"
        )
    return {
        "size": len(data),
        "git_blob_sha1": actual_blob,
        "sha256": actual_sha256,
    }


def materialize_assets(
    recipe: dict[str, Any],
    assets: list[dict[str, Any]],
    corpus_root: Path,
    *,
    timeout: int,
) -> list[dict[str, Any]]:
    corpus_root.mkdir(parents=True, exist_ok=True)
    materialized: list[dict[str, Any]] = []
    for asset in assets:
        provider = recipe["providers"][str(asset["provider"])]
        repository = str(provider["repository"])
        commit = str(provider["commit"]).lower()
        upstream_path = str(asset["upstream_path"])
        destination = corpus_root / _safe_relative_path(
            str(asset["local_path"]), field=f"asset {asset['id']} local_path"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        url = raw_github_url(repository, commit, upstream_path)

        if destination.is_file():
            data = destination.read_bytes()
            try:
                verified = _verify_asset_bytes(asset, data)
                source = "cache"
            except BaselineError:
                data = _download(url, timeout=timeout)
                verified = _verify_asset_bytes(asset, data)
                destination.write_bytes(data)
                source = "download"
        else:
            data = _download(url, timeout=timeout)
            verified = _verify_asset_bytes(asset, data)
            destination.write_bytes(data)
            source = "download"

        materialized.append(
            {
                **asset,
                **verified,
                "repository": repository,
                "commit": commit,
                "materialized_from": source,
            }
        )
        print(
            f"[source] {asset['id']}: {source}, {verified['size']} bytes, "
            f"sha256={verified['sha256']}"
        )
    return materialized


def build_evaluator_manifest(
    recipe: dict[str, Any],
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA,
        "kind": "external_blind_holdout",
        "evaluation_class": "external_baseline",
        "protocol": {
            "independent_from_rule_authoring": False,
            "ground_truth_prepared_without_breachscope_findings": True,
            "final_holdout_seen_before_rule_freeze": True,
        },
        "files": [
            {
                "path": str(row["local_path"]),
                "format": str(row["format"]).lower(),
                "sha256": str(row["sha256"]).lower(),
            }
            for row in assets
        ],
        "scenarios": [
            {
                "scenario_id": str(row["scenario_id"]),
                "source_files": [str(row["local_path"])],
                "expected_techniques": [
                    str(item).upper() for item in row["expected_techniques"]
                ],
            }
            for row in assets
        ],
        "provenance": {
            "baseline_id": recipe["baseline_id"],
            "public_known_corpus": True,
            "final_blind_holdout": False,
            "raw_samples_redistributed_by_breachscope": False,
            "sources": [
                {
                    "asset_id": row["id"],
                    "provider": row["provider"],
                    "repository": row["repository"],
                    "commit": row["commit"],
                    "upstream_path": row["upstream_path"],
                    "git_blob_sha1": row["git_blob_sha1"],
                    "sha256": row["sha256"],
                    "size": row["size"],
                    "mapping_basis": row["mapping_basis"],
                }
                for row in assets
            ],
        },
    }


def write_ignore_labels(index_path: Path, labels_path: Path) -> int:
    count = 0
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("r", encoding="utf-8") as source, labels_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as target:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            key = str(row.get("event_key") or "").strip()
            if len(key) != 64:
                raise BaselineError(f"invalid event_key in index line {line_number}")
            target.write(
                json.dumps(
                    {
                        "event_key": key,
                        "label": "ignore",
                        "expected_techniques": [],
                        "notes": (
                            "P2-09C attack-corpus baseline: event-level ground truth "
                            "is intentionally not asserted."
                        ),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            count += 1
    if count == 0:
        raise BaselineError("event index contains zero events")
    return count


def _run(command: list[str]) -> None:
    print("[run]", " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def _write_summary(
    result: dict[str, Any],
    recipe: dict[str, Any],
    materialized: list[dict[str, Any]],
    out_dir: Path,
) -> None:
    scenarios = result["scenarios"]
    payload = {
        "schema": "breachscope.p2_09c_external_baseline_summary.v1",
        "baseline_id": recipe["baseline_id"],
        "evaluation_class": result["claim_boundary"]["evaluation_class"],
        "repo_commit": result["freeze"]["repo_commit"],
        "rules_tree_sha256": result["freeze"]["rules_tree_sha256"],
        "corpus": result["corpus"],
        "primary_metrics": {
            "scenario_hits": scenarios["hits"],
            "scenario_misses": scenarios["misses"],
            "scenario_total": scenarios["total"],
            "scenario_hit_rate": scenarios["hit_rate"],
        },
        "event_level_metrics": {
            "precision": "NOT_CLAIMED",
            "recall": "NOT_CLAIMED",
            "false_positive_rate": "NOT_CLAIMED",
            "reason": (
                "All attack-corpus events are labeled ignore because the public "
                "samples do not provide event-by-event malicious/benign ground truth."
            ),
        },
        "detection_observation": {
            "findings": result["detection"]["findings"],
            "flagged_events": result["detection"]["flagged_events"],
            "flagged_ignored_events": result["detection"]["flagged_ignored_events"],
        },
        "performance_observation": result["performance"],
        "scenarios": scenarios["outcomes"],
        "sources": [
            {
                "asset_id": row["id"],
                "repository": row["repository"],
                "commit": row["commit"],
                "upstream_path": row["upstream_path"],
                "git_blob_sha1": row["git_blob_sha1"],
                "sha256": row["sha256"],
                "size": row["size"],
            }
            for row in materialized
        ],
        "claim_boundary": {
            "public_known_corpus": True,
            "final_blind_holdout": False,
            "production_detection_quality_certified": False,
            "benign_false_positive_rate_measured": False,
            "next_required_phase": "P2-09D real benign baseline",
        },
    }
    (out_dir / "summary.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )

    lines = [
        "# P2-09C External Attack Baseline",
        "",
        f"- Baseline: `{payload['baseline_id']}`",
        f"- Repo commit: `{payload['repo_commit']}`",
        f"- Scenarios: **{scenarios['hits']} hit / {scenarios['misses']} miss / {scenarios['total']} total**",
        f"- Scenario hit rate: **{scenarios['hit_rate']:.1%}**",
        f"- Findings observed: **{result['detection']['findings']}**",
        f"- Events: **{result['corpus']['events']}** (all event labels are `ignore`)",
        "",
        "## Scenario outcomes",
        "",
        "| Scenario | Expected | Matched | Missing | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in scenarios["outcomes"]:
        lines.append(
            "| {scenario} | {expected} | {matched} | {missing} | {status} |".format(
                scenario=row["scenario_id"],
                expected=", ".join(row["expected_techniques"]) or "-",
                matched=", ".join(row["matched_techniques"]) or "-",
                missing=", ".join(row["missing_techniques"]) or "-",
                status=row["status"].upper(),
            )
        )
    lines.extend(
        [
            "",
            "## Claim boundary",
            "",
            "- This is a public, known external attack corpus, not a final blind holdout.",
            "- Event-level precision, recall, and false-positive rate are **not claimed**.",
            "- A scenario hit means the expected ATT&CK technique was observed somewhere in that scenario's source file.",
            "- P2-09D must measure false positives on real benign Windows logs.",
            "- Misses are retained as evidence; this runner does not modify detection rules.",
            "",
        ]
    )
    (out_dir / "SUMMARY.md").write_text(
        "\n".join(lines), encoding="utf-8", newline="\n"
    )


def run_baseline(args: argparse.Namespace) -> int:
    recipe_path = Path(args.recipe).resolve()
    recipe = load_recipe(recipe_path)
    assets = select_assets(recipe, args.asset)

    if args.validate_only:
        print(
            f"P2-09C source recipe: PASS "
            f"({len(recipe['providers'])} providers, {len(recipe['assets'])} pinned assets)"
        )
        print("Network access: NOT USED")
        print("Detection rules executed: NO")
        return 0

    out_dir = Path(args.out).resolve()
    corpus_root = out_dir / "corpus"
    freeze_path = out_dir / "rules_freeze.json"
    manifest_path = out_dir / "manifest.yaml"
    index_path = out_dir / "event_index.jsonl"
    labels_path = out_dir / "labels_ignore.jsonl"
    result_path = out_dir / "result.json"

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

    materialized = materialize_assets(
        recipe, assets, corpus_root, timeout=args.timeout
    )
    manifest = build_evaluator_manifest(recipe, materialized)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
        newline="\n",
    )

    _run(
        [
            sys.executable,
            str(EVALUATOR),
            "index",
            "--manifest",
            str(manifest_path),
            "--corpus-root",
            str(corpus_root),
            "--out",
            str(index_path),
        ]
    )
    label_count = write_ignore_labels(index_path, labels_path)
    print(f"[labels] {label_count} events -> ignore (event-level GT not asserted)")

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
            str(corpus_root),
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

    result = json.loads(result_path.read_text(encoding="utf-8"))
    _write_summary(result, recipe, materialized, out_dir)
    print("P2-09C baseline complete:", out_dir)
    print(
        "Scenario hit rate: "
        f"{result['scenarios']['hits']}/{result['scenarios']['total']} "
        f"({result['scenarios']['hit_rate']:.1%})"
    )
    print("Event-level precision/recall/FPR: NOT CLAIMED")
    return 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Run BreachScope P2-09C pinned external attack baseline."
    )
    ap.add_argument("--recipe", default=str(DEFAULT_RECIPE))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument(
        "--asset",
        action="append",
        help="Run only a named asset. Repeat to select multiple assets.",
    )
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the pinned source recipe without network or detection.",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run_baseline(args)
    except (BaselineError, OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"P2-09C ERROR: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(
            f"P2-09C ERROR: subprocess failed with exit code {exc.returncode}",
            file=sys.stderr,
        )
        return int(exc.returncode or 2)


if __name__ == "__main__":
    raise SystemExit(main())
