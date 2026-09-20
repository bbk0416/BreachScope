#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "breachscope.p2_26c_gha_windows_benign_one_pass.v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def acquire_permanent_lock(path: Path, analysis_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(f"one-pass lock already exists: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(
            {"analysis_id": analysis_id, "pid": os.getpid(), "created_unix": time.time()},
            handle,
        )


def load_product(product_repo: Path):
    sys.path.insert(0, str(product_repo))
    from breachscope.analyzer import apply_rules
    from breachscope.ingest import _extract_from_xml
    from breachscope.rules import load_rules
    from breachscope.schemas import Event
    from scripts.evaluate_external_holdout import rules_tree_hash

    return apply_rules, _extract_from_xml, load_rules, Event, rules_tree_hash


def verify_product(product_repo: Path, contract: dict[str, Any], rules_tree_hash, load_rules) -> dict[str, Any]:
    frozen = contract["frozen_product"]
    head = git(product_repo, "rev-parse", "HEAD")
    dirty = git(product_repo, "status", "--porcelain", "-uall")
    rule_hash, rule_files = rules_tree_hash(product_repo / "rules")
    rules = load_rules(product_repo / "rules")
    if head != frozen["repo_commit"]:
        raise RuntimeError(f"product commit mismatch: {head}")
    if dirty:
        raise RuntimeError("product worktree is dirty")
    if rule_hash != frozen["rules_tree_sha256"]:
        raise RuntimeError(f"rule tree mismatch: {rule_hash}")
    if len(rules) != frozen["rule_count"]:
        raise RuntimeError(f"rule count mismatch: {len(rules)}")
    if rule_files != frozen["rule_file_count"]:
        raise RuntimeError(f"rule file count mismatch: {rule_files}")
    return {
        "repo_commit": head,
        "rules_tree_sha256": rule_hash,
        "rule_file_count": rule_files,
        "rule_count": len(rules),
    }


def to_event(xml: str, parser, Event):
    row = parser(xml)
    if not isinstance(row, dict):
        raise ValueError("product XML parser returned non-mapping")
    keys = ("timestamp", "host", "source", "event_id", "level", "user", "command_line", "raw")
    return Event(**{key: row.get(key) for key in keys})


def load_evtx(path: Path, parser, Event) -> tuple[list[Any], int]:
    from Evtx.Evtx import Evtx

    events: list[Any] = []
    parse_errors = 0
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                events.append(to_event(record.xml(), parser, Event))
            except Exception:
                parse_errors += 1
    return events, parse_errors


def verify_source_identity(data_dir: Path, contract: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = contract["source_identity"]
    identity_path = data_dir / "identity.json"
    if sha256(identity_path) != source["identity_json_sha256"]:
        raise RuntimeError("identity.json SHA256 mismatch")

    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    expected_scalar = {
        "schema": "breachscope.p2_26c_gha_windows_benign_source_identity.v1",
        "analysis_id": contract["analysis_id"],
        "status": "IDENTITY_CAPTURED",
        "binding_merge_commit": source["binding_merge_commit"],
        "workflow_run_id": str(source["workflow_run_id"]),
        "workflow_run_attempt": "1",
        "runner_os": "Windows",
        "runner_arch": "X64",
        "image_os": source["image_os"],
        "image_version": source["image_version"],
        "repository_checkout_before_collection": False,
        "repository_code_executed_before_collection": False,
        "evtx_records_parsed": False,
        "breachscope_detector_executed": False,
        "collection_window_milliseconds": 900000,
    }
    for key, expected in expected_scalar.items():
        if identity.get(key) != expected:
            raise RuntimeError(f"identity field mismatch: {key}: {identity.get(key)!r} != {expected!r}")

    expected_files = source["files"]
    observed_files = identity.get("files")
    if observed_files != expected_files:
        raise RuntimeError("identity file list does not match frozen contract")

    expected_names = sorted(row["filename"] for row in expected_files)
    actual_names = sorted(path.name for path in data_dir.glob("*.evtx"))
    if actual_names != expected_names:
        raise RuntimeError(f"EVTX member list mismatch: {actual_names!r}")

    verified: list[dict[str, Any]] = []
    for row in expected_files:
        path = data_dir / row["filename"]
        actual = {
            "channel": row["channel"],
            "filename": row["filename"],
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        actual["size_match"] = actual["size_bytes"] == row["size_bytes"]
        actual["sha256_match"] = actual["sha256"] == row["sha256"]
        if not actual["size_match"] or not actual["sha256_match"]:
            raise RuntimeError(f"source identity mismatch: {row['filename']}")
        verified.append(actual)
    return identity, verified


def preflight(args: argparse.Namespace) -> int:
    product_repo = Path(args.product_repo).resolve()
    contract_path = Path(args.contract).resolve()
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    apply_rules, parser, load_rules, Event, rules_tree_hash = load_product(product_repo)
    del apply_rules, parser, Event
    frozen = verify_product(product_repo, contract, rules_tree_hash, load_rules)
    runner_hash = text_sha256(Path(__file__).resolve())
    if runner_hash != contract["runner"]["sha256"]:
        raise RuntimeError("runner SHA mismatch")
    print(json.dumps({"status": "PRECHECK_PASS", **frozen, "runner_sha256": runner_hash}, sort_keys=True))
    return 0


def run(args: argparse.Namespace) -> int:
    product_repo = Path(args.product_repo).resolve()
    contract_path = Path(args.contract).resolve()
    data_dir = Path(args.data_dir).resolve()
    out = Path(args.out).resolve()
    lock = Path(args.lock).resolve()
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))

    acquire_permanent_lock(lock, contract["analysis_id"])
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "analysis_id": contract["analysis_id"],
        "status": "started",
        "contract_sha256": sha256(contract_path),
        "runner_sha256": text_sha256(Path(__file__).resolve()),
        "python": sys.version,
        "channels": [],
    }
    atomic_write(out, payload)
    try:
        if payload["runner_sha256"] != contract["runner"]["sha256"]:
            raise RuntimeError("runner SHA mismatch")

        apply_rules, parser, load_rules, Event, rules_tree_hash = load_product(product_repo)
        payload["frozen_product"] = verify_product(product_repo, contract, rules_tree_hash, load_rules)
        rules = load_rules(product_repo / "rules")

        identity, verified = verify_source_identity(data_dir, contract)
        payload["source_identity"] = {
            "workflow_run_id": identity["workflow_run_id"],
            "workflow_run_attempt": identity["workflow_run_attempt"],
            "binding_merge_commit": identity["binding_merge_commit"],
            "image_os": identity["image_os"],
            "image_version": identity["image_version"],
            "artifact_id": contract["source_identity"]["artifact_id"],
            "artifact_name": contract["source_identity"]["artifact_name"],
            "artifact_zip_sha256": contract["source_identity"]["artifact_zip_sha256"],
            "identity_json_sha256": contract["source_identity"]["identity_json_sha256"],
        }
        payload["source_verification"] = verified
        payload["status"] = "sources_verified"
        atomic_write(out, payload)

        overall = time.perf_counter()
        total_parsed = 0
        total_parse_errors = 0
        total_findings = 0
        total_flagged = 0
        aggregate_rule_findings: Counter[str] = Counter()
        aggregate_rule_flagged: dict[str, set[tuple[str, int]]] = defaultdict(set)

        for source in contract["source_identity"]["files"]:
            row: dict[str, Any] = {
                "channel": source["channel"],
                "filename": source["filename"],
                "stage": "started",
            }
            payload["channels"].append(row)
            atomic_write(out, payload)
            try:
                started = time.perf_counter()
                events, parse_errors = load_evtx(data_dir / source["filename"], parser, Event)
                row.update(
                    stage="parsed",
                    parsed_events=len(events),
                    parse_errors=parse_errors,
                    parse_seconds=time.perf_counter() - started,
                )
                atomic_write(out, payload)

                started = time.perf_counter()
                findings = list(apply_rules(events, rules))
                flagged_event_ids = {id(f.event) for f in findings}
                rule_findings = Counter(str(getattr(f, "rule_id", "") or "") for f in findings)
                event_indexes = {id(event): index for index, event in enumerate(events)}
                rule_flagged: dict[str, set[int]] = defaultdict(set)
                for finding in findings:
                    rule_id = str(getattr(finding, "rule_id", "") or "")
                    event_id = id(finding.event)
                    rule_flagged[rule_id].add(event_id)
                    aggregate_rule_flagged[rule_id].add(
                        (source["filename"], event_indexes[event_id])
                    )
                aggregate_rule_findings.update(rule_findings)

                row.update(
                    stage="completed",
                    findings=len(findings),
                    flagged_events=len(flagged_event_ids),
                    findings_by_rule=dict(sorted(rule_findings.items())),
                    flagged_events_by_rule={key: len(value) for key, value in sorted(rule_flagged.items())},
                    detection_seconds=time.perf_counter() - started,
                )
                total_parsed += len(events)
                total_parse_errors += parse_errors
                total_findings += len(findings)
                total_flagged += len(flagged_event_ids)
                atomic_write(out, payload)
            except BaseException as exc:
                row.update(stage="failed", error=f"{type(exc).__name__}: {exc}")
                atomic_write(out, payload)
                raise

        if total_parsed <= 0:
            raise RuntimeError("canonical benign corpus parsed zero events")

        fraction = total_flagged / total_parsed
        payload["summary"] = {
            "channel_count": len(contract["source_identity"]["files"]),
            "parsed_events": total_parsed,
            "parse_errors": total_parse_errors,
            "findings": total_findings,
            "flagged_events": total_flagged,
            "observed_source_intent_benign_flagged_event_fraction": fraction,
            "observed_source_intent_benign_flagged_event_percent": fraction * 100.0,
            "findings_by_rule": dict(sorted(aggregate_rule_findings.items())),
            "flagged_events_by_rule": {
                key: len(value) for key, value in sorted(aggregate_rule_flagged.items())
            },
            "wall_seconds": time.perf_counter() - overall,
        }
        payload["claim_boundary"] = {
            "source_population_intent": "BENIGN_CI_BASELINE",
            "event_level_benign_ground_truth": "NOT_AVAILABLE",
            "event_level_manual_adjudication": False,
            "observed_fraction_is_confirmed_false_positive_rate": False,
            "confirmed_false_positive_rate": "NOT_CLAIMED",
            "general_fresh_full_benign_fpr": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "representative_production_population": "NOT_CLAIMED",
        }
        payload["status"] = "completed"
        atomic_write(out, payload)
        print(json.dumps(payload["summary"], sort_keys=True))
        return 0
    except BaseException as exc:
        payload.update(
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            measurement={"status": "FAILED_CANONICAL"},
        )
        atomic_write(out, payload)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Run preregistered P2-26C fresh Windows CI benign revalidation.")
    parser.add_argument("--product-repo", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--data-dir")
    parser.add_argument("--out")
    parser.add_argument("--lock")
    args = parser.parse_args()
    if args.preflight:
        return preflight(args)
    if not all((args.data_dir, args.out, args.lock)):
        parser.error("--data-dir, --out and --lock are required for a run")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
