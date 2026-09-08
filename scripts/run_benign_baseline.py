#!/usr/bin/env python3
"""Run the pinned P2-09D benign Windows EVTX baseline."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "scripts" / "evaluate_external_holdout.py"
DEFAULT_RECIPE = ROOT / "external_baseline" / "p2_09d_benign_sources.yaml"
DEFAULT_OUT = ROOT / "out" / "external_baseline" / "p2_09d"

SCHEMA = "breachscope.benign_baseline_sources.v1"
EVALUATOR_SCHEMA = "breachscope.external_holdout.v1"
SUMMARY_SCHEMA = "breachscope.p2_09d_benign_baseline_summary.v1"


class BaselineError(RuntimeError):
    pass


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def validate_recipe(recipe: dict[str, Any]) -> dict[str, Any]:
    if recipe.get("schema") != SCHEMA:
        raise BaselineError(f"recipe schema must be {SCHEMA!r}")
    if str(recipe.get("evaluation_class") or "").strip() != "external_baseline":
        raise BaselineError("evaluation_class must be external_baseline")
    baseline_id = str(recipe.get("baseline_id") or "").strip()
    if not baseline_id:
        raise BaselineError("baseline_id is required")

    label_policy = str(recipe.get("label_policy") or "").strip()
    if label_policy != "benign_by_source_intent":
        raise BaselineError("label_policy must be benign_by_source_intent")

    source = recipe.get("source")
    if not isinstance(source, dict):
        raise BaselineError("source mapping is required")

    required_text = (
        "repository",
        "release_tag",
        "asset_name",
        "asset_url",
        "sha256",
        "license",
        "provenance_note",
    )
    for key in required_text:
        if not str(source.get(key) or "").strip():
            raise BaselineError(f"source.{key} is required")

    for key in ("release_id", "asset_id", "size"):
        value = source.get(key)
        if not isinstance(value, int) or value <= 0:
            raise BaselineError(f"source.{key} must be a positive integer")

    digest = str(source["sha256"]).strip().lower()
    if not _is_sha256(digest):
        raise BaselineError("source.sha256 must be a lowercase 64-character SHA-256")
    source["sha256"] = digest

    url = str(source["asset_url"]).strip()
    if not url.startswith("https://"):
        raise BaselineError("source.asset_url must use https")

    if not str(source["asset_name"]).casefold().endswith((".tgz", ".tar.gz")):
        raise BaselineError("source.asset_name must be a .tgz or .tar.gz archive")

    claim_boundary = recipe.get("claim_boundary")
    if not isinstance(claim_boundary, dict):
        raise BaselineError("claim_boundary mapping is required")
    if claim_boundary.get("production_false_positive_rate") != "not_claimed":
        raise BaselineError(
            "claim_boundary.production_false_positive_rate must be not_claimed"
        )
    if claim_boundary.get("event_level_manual_adjudication") is not False:
        raise BaselineError(
            "claim_boundary.event_level_manual_adjudication must be false"
        )

    return recipe


def load_recipe(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise BaselineError("benign baseline recipe must be a YAML mapping")
    return validate_recipe(data)


def _download(url: str, destination: Path, timeout: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "BreachScope-P2-09D/1.0"},
    )
    temp_path = destination.with_name(destination.name + ".part")
    temp_path.unlink(missing_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, temp_path.open(
            "wb"
        ) as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        temp_path.replace(destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def verify_archive(path: Path, source: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        raise BaselineError(f"archive not found: {path}")
    actual_size = path.stat().st_size
    expected_size = int(source["size"])
    if actual_size != expected_size:
        raise BaselineError(
            f"archive size mismatch: expected={expected_size} actual={actual_size}"
        )
    actual_sha256 = _sha256_path(path)
    expected_sha256 = str(source["sha256"]).lower()
    if actual_sha256 != expected_sha256:
        raise BaselineError(
            "archive SHA-256 mismatch: "
            f"expected={expected_sha256} actual={actual_sha256}"
        )
    return {
        "size": actual_size,
        "sha256": actual_sha256,
    }


def materialize_archive(
    recipe: dict[str, Any], raw_root: Path, timeout: int
) -> tuple[Path, dict[str, Any]]:
    source = recipe["source"]
    archive_path = raw_root / str(source["asset_name"])
    if archive_path.is_file():
        try:
            verified = verify_archive(archive_path, source)
            print(f"[reuse] {archive_path}")
            return archive_path, verified
        except BaselineError:
            archive_path.unlink(missing_ok=True)

    print(f"[download] {source['asset_url']}")
    _download(str(source["asset_url"]), archive_path, timeout)
    verified = verify_archive(archive_path, source)
    return archive_path, verified


def _validated_member_path(member_name: str) -> PurePosixPath:
    rel = PurePosixPath(member_name)
    if rel.is_absolute():
        raise BaselineError(f"unsafe absolute archive path: {member_name}")
    parts = tuple(part for part in rel.parts if part not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        raise BaselineError(f"unsafe archive path: {member_name}")
    return PurePosixPath(*parts)


def extract_evtx_archive(
    archive_path: Path, corpus_root: Path
) -> list[dict[str, Any]]:
    corpus_root.mkdir(parents=True, exist_ok=True)
    root = corpus_root.resolve()

    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = []
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if not member.name.casefold().endswith(".evtx"):
                continue
            rel = _validated_member_path(member.name)
            members.append((member, rel))

        if not members:
            raise BaselineError("benign baseline archive contains no EVTX files")

        extracted: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for member, rel in members:
            rel_text = rel.as_posix()
            if rel_text in seen_paths:
                raise BaselineError(f"duplicate EVTX path in archive: {rel_text}")
            seen_paths.add(rel_text)

            target = (root / Path(*rel.parts)).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise BaselineError(f"archive path escapes corpus root: {rel_text}") from exc

            source = archive.extractfile(member)
            if source is None:
                raise BaselineError(f"could not read archive member: {rel_text}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)

            if target.stat().st_size != member.size:
                raise BaselineError(
                    f"extracted size mismatch for {rel_text}: "
                    f"expected={member.size} actual={target.stat().st_size}"
                )
            extracted.append(
                {
                    "path": rel_text,
                    "format": "evtx",
                    "sha256": _sha256_path(target),
                    "size": member.size,
                }
            )

    extracted.sort(key=lambda row: str(row["path"]))
    return extracted


def build_evaluator_manifest(
    recipe: dict[str, Any],
    files: list[dict[str, Any]],
    archive_verification: dict[str, Any],
) -> dict[str, Any]:
    source = recipe["source"]
    return {
        "schema": EVALUATOR_SCHEMA,
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
                "format": "evtx",
                "sha256": row["sha256"],
            }
            for row in files
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
            "production_false_positive_rate_claimed": False,
            "event_level_manual_adjudication": False,
        },
    }


def write_benign_labels(index_path: Path, labels_path: Path) -> int:
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
            if len(key) != 64 or not all(ch in "0123456789abcdef" for ch in key):
                raise BaselineError(f"invalid event_key in index line {line_number}")
            target.write(
                json.dumps(
                    {
                        "event_key": key,
                        "label": "benign",
                        "expected_techniques": [],
                        "notes": (
                            "P2-09D benign-by-source-intent label from the pinned "
                            "Nextron evtx-baseline goodware corpus; not manually "
                            "adjudicated event by event."
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


def _safe_rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _write_summary(
    result: dict[str, Any],
    recipe: dict[str, Any],
    archive_verification: dict[str, Any],
    extracted_files: list[dict[str, Any]],
    out_dir: Path,
) -> dict[str, Any]:
    corpus = result["corpus"]
    detection = result["detection"]
    confusion = detection["confusion"]

    if int(corpus.get("malicious", -1)) != 0:
        raise BaselineError("benign baseline unexpectedly contains malicious labels")
    if int(corpus.get("ignore", -1)) != 0:
        raise BaselineError("benign baseline unexpectedly contains ignore labels")
    if int(confusion.get("tp", -1)) != 0 or int(confusion.get("fn", -1)) != 0:
        raise BaselineError("benign baseline produced malicious confusion-matrix counts")

    benign_events = int(corpus["benign"])
    false_positives = int(confusion["fp"])
    true_negatives = int(confusion["tn"])
    if false_positives + true_negatives != benign_events:
        raise BaselineError("benign confusion matrix does not cover every scored event")

    per_source = []
    for source_file, row in result["per_source"].items():
        events = int(row["events"])
        flagged = int(row["flagged"])
        per_source.append(
            {
                "source_file": source_file,
                "events": events,
                "flagged_events": flagged,
                "flagged_event_rate": _safe_rate(flagged, events),
            }
        )
    per_source.sort(
        key=lambda row: (-int(row["flagged_events"]), -int(row["events"]), row["source_file"])
    )

    payload = {
        "schema": SUMMARY_SCHEMA,
        "baseline_id": recipe["baseline_id"],
        "evaluation_class": "external_baseline",
        "repo_commit": result["freeze"]["repo_commit"],
        "rules_tree_sha256": result["freeze"]["rules_tree_sha256"],
        "source": {
            **recipe["source"],
            "verified_size": archive_verification["size"],
            "verified_sha256": archive_verification["sha256"],
            "extracted_evtx_files": len(extracted_files),
        },
        "corpus": {
            "events": benign_events,
            "source_files": int(corpus["source_files"]),
            "label_policy": recipe["label_policy"],
            "event_level_manual_adjudication": False,
        },
        "primary_metrics": {
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_positive_rate": float(detection["false_positive_rate"]),
            "flagged_events": int(detection["flagged_events"]),
            "findings": int(detection["findings"]),
            "flagged_events_per_1000": _safe_rate(false_positives * 1000, benign_events),
            "findings_per_1000": _safe_rate(int(detection["findings"]) * 1000, benign_events),
        },
        "performance_observation": result["performance"],
        "per_source": per_source,
        "claim_boundary": {
            "benign_by_source_intent": True,
            "event_level_manual_adjudication": False,
            "production_false_positive_rate_measured": False,
            "enterprise_environment_representative": False,
            "final_blind_holdout": False,
            "interpretation": (
                "The false-positive rate applies only to this pinned goodware corpus. "
                "It is not a production or enterprise-wide false-positive estimate."
            ),
            "next_required_phase": "P2-09E reproducible benchmark",
        },
    }

    (out_dir / "summary.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )

    top_flagged = [row for row in per_source if int(row["flagged_events"]) > 0][:20]
    lines = [
        "# P2-09D Real Benign Baseline",
        "",
        f"- Baseline: `{payload['baseline_id']}`",
        f"- Repo commit: `{payload['repo_commit']}`",
        f"- Benign events: **{benign_events}**",
        f"- EVTX files: **{len(extracted_files)}**",
        f"- False positives: **{false_positives}**",
        f"- True negatives: **{true_negatives}**",
        f"- Baseline false-positive rate: **{payload['primary_metrics']['false_positive_rate']:.6%}**",
        f"- Flagged events / 1,000: **{payload['primary_metrics']['flagged_events_per_1000']:.3f}**",
        f"- Findings / 1,000: **{payload['primary_metrics']['findings_per_1000']:.3f}**",
        "",
        "## Most flagged source files",
        "",
        "| Source file | Events | Flagged events | Flagged rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    if top_flagged:
        for row in top_flagged:
            lines.append(
                f"| {row['source_file']} | {row['events']} | {row['flagged_events']} | "
                f"{row['flagged_event_rate']:.4%} |"
            )
    else:
        lines.append("| - | 0 | 0 | 0.0000% |")

    lines.extend(
        [
            "",
            "## Claim boundary",
            "",
            "- The source is a pinned public goodware/user-activity EVTX baseline.",
            "- Every event is labeled benign from corpus provenance, not by manual event-by-event adjudication.",
            "- The measured false-positive rate applies only to this exact corpus.",
            "- This does not establish a production or enterprise-wide false-positive rate.",
            "- Raw third-party EVTX files are kept under ignored `out/` paths and are not committed.",
            "",
        ]
    )
    (out_dir / "SUMMARY.md").write_text(
        "\n".join(lines), encoding="utf-8", newline="\n"
    )
    return payload


def run_baseline(args: argparse.Namespace) -> int:
    recipe_path = Path(args.recipe).resolve()
    recipe = load_recipe(recipe_path)

    if args.validate_only:
        source = recipe["source"]
        print(
            "P2-09D source recipe: PASS "
            f"({source['repository']} {source['release_tag']} / {source['asset_name']})"
        )
        print("Network access: NOT USED")
        print("Detection rules executed: NO")
        return 0

    out_dir = Path(args.out).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    raw_root = out_dir / "raw"
    corpus_root = out_dir / "corpus"
    freeze_path = out_dir / "rules_freeze.json"
    manifest_path = out_dir / "manifest.yaml"
    index_path = out_dir / "event_index.jsonl"
    labels_path = out_dir / "labels_benign.jsonl"
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

    archive_path, archive_verification = materialize_archive(
        recipe, raw_root, timeout=args.timeout
    )
    extracted_files = extract_evtx_archive(archive_path, corpus_root)
    print(f"[extract] {len(extracted_files)} EVTX files")

    manifest = build_evaluator_manifest(
        recipe, extracted_files, archive_verification
    )
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
    label_count = write_benign_labels(index_path, labels_path)
    print(f"[labels] {label_count} events -> benign_by_source_intent")

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
    summary = _write_summary(
        result,
        recipe,
        archive_verification,
        extracted_files,
        out_dir,
    )
    metrics = summary["primary_metrics"]
    print("P2-09D benign baseline complete:", out_dir)
    print(
        "False positives: "
        f"{metrics['false_positives']}/{summary['corpus']['events']} "
        f"({metrics['false_positive_rate']:.6%})"
    )
    print("Production false-positive rate: NOT CLAIMED")
    return 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Run BreachScope P2-09D pinned benign Windows EVTX baseline."
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
    except (BaselineError, OSError, json.JSONDecodeError, tarfile.TarError, yaml.YAMLError) as exc:
        print(f"P2-09D ERROR: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(
            f"P2-09D ERROR: subprocess failed with exit code {exc.returncode}",
            file=sys.stderr,
        )
        return int(exc.returncode or 2)


if __name__ == "__main__":
    raise SystemExit(main())
