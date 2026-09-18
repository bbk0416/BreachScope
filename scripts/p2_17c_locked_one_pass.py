#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "breachscope.p2_17c_locked_one_pass_measurement.v1"

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, path)
def acquire_permanent_lock(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(f"one-pass lock already exists: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"pid": os.getpid(), "created_unix": time.time()}, f)

def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

def finding_techniques(finding: Any) -> set[str]:
    values = list(getattr(finding, "mitre_techniques", None) or [])
    primary = getattr(finding, "mitre_technique", None)
    if primary:
        values.append(primary)
    return {str(value).strip().upper() for value in values if str(value or "").strip()}

def load_product(product_repo: Path):
    sys.path.insert(0, str(product_repo))
    from breachscope.analyzer import apply_rules
    from breachscope.attack_annotations import attack_requirement_satisfied
    from breachscope.correlator import correlate_events
    from breachscope.ingest import _extract_from_xml
    from breachscope.rules import load_rules
    from breachscope.scenario import infer_scenarios
    from breachscope.schemas import Event
    from scripts.evaluate_external_holdout import rules_tree_hash
    return (apply_rules, attack_requirement_satisfied, correlate_events,
            _extract_from_xml, load_rules, infer_scenarios, Event, rules_tree_hash)
def verify_frozen_state(product_repo: Path, binding: dict[str, Any], rules_tree_hash) -> dict[str, Any]:
    code = binding["code_under_observation"]
    head = git(product_repo, "rev-parse", "HEAD")
    dirty = git(product_repo, "status", "--porcelain", "-uall")
    rule_hash, rule_files = rules_tree_hash(product_repo / "rules")
    if head != code["repo_commit"]:
        raise RuntimeError(f"product commit mismatch: {head}")
    if dirty:
        raise RuntimeError("product worktree is dirty")
    if rule_hash != code["rules_tree_sha256"]:
        raise RuntimeError(f"rule tree mismatch: {rule_hash}")
    return {"repo_commit": head, "rules_tree_sha256": rule_hash, "rule_file_count": rule_files}

def to_event(xml: str, parser, Event):
    row = parser(xml)
    if not isinstance(row, dict):
        raise ValueError("product XML parser returned non-mapping")
    keys = ("timestamp", "host", "source", "event_id", "level", "user", "command_line", "raw")
    return Event(**{key: row.get(key) for key in keys})

def update_peak(row: dict[str, Any]) -> None:
    if tracemalloc.is_tracing():
        _, peak = tracemalloc.get_traced_memory()
        row["peak_python_memory_mb"] = peak / (1024 * 1024)

def preflight(args: argparse.Namespace) -> int:
    product_repo = Path(args.product_repo).resolve()
    binding_path = Path(args.binding).resolve()
    binding = yaml.safe_load(binding_path.read_text(encoding="utf-8"))
    parts = load_product(product_repo)
    frozen = verify_frozen_state(product_repo, binding, parts[-1])
    rules = parts[4](product_repo / "rules")
    payload = {"status": "PRECHECK_PASS", **frozen, "rule_count": len(rules),
               "runner_sha256": sha256(Path(__file__).resolve())}
    print(json.dumps(payload, sort_keys=True))
    return 0
def run(args: argparse.Namespace) -> int:
    product_repo = Path(args.product_repo).resolve()
    binding_path = Path(args.binding).resolve()
    data_dir = Path(args.data_dir).resolve()
    out = Path(args.out).resolve()
    lock = Path(args.lock).resolve()
    acquire_permanent_lock(lock)
    binding = yaml.safe_load(binding_path.read_text(encoding="utf-8"))
    expected_runner = binding["runner"]["sha256"]
    actual_runner = sha256(Path(__file__).resolve())
    payload: dict[str, Any] = {
        "schema": SCHEMA, "analysis_id": binding["analysis_id"],
        "status": "started", "binding_sha256": sha256(binding_path),
        "runner_sha256": actual_runner, "datasets": [],
        "python": sys.version,
    }
    atomic_write(out, payload)
    if actual_runner != expected_runner:
        payload.update(status="failed", error="runner SHA mismatch")
        atomic_write(out, payload)
        return 2
    parts = load_product(product_repo)
    apply_rules, satisfies, correlate, parser, load_rules, infer, Event, hash_rules = parts
    try:
        payload["frozen_state"] = verify_frozen_state(product_repo, binding, hash_rules)
        rules = load_rules(product_repo / "rules")
        payload["rule_count"] = len(rules)
        payload["status"] = "preflight_passed"
        atomic_write(out, payload)
    except BaseException as exc:
        payload.update(status="preflight_failed", error=f"{type(exc).__name__}: {exc}")
        atomic_write(out, payload)
        return 3
    overall = time.perf_counter()
    for source in binding["datasets"]:
        row: dict[str, Any] = {
            "technique_id": source["technique_id"],
            "local_filename": source["local_filename"],
            "stage": "started",
        }
        payload["datasets"].append(row)
        atomic_write(out, payload)
        try:
            path = data_dir / source["local_filename"]
            actual_sha, actual_size = sha256(path), path.stat().st_size
            row["source_verification"] = {
                "sha256": actual_sha, "size_bytes": actual_size,
                "sha_match": actual_sha == source["telemetry_sha256"],
                "size_match": actual_size == source["telemetry_size_bytes"],
            }
            if not row["source_verification"]["sha_match"] or not row["source_verification"]["size_match"]:
                raise RuntimeError("source hash or size mismatch")
            row["stage"] = "source_verified"
            atomic_write(out, payload)
            tracemalloc.start()
            started = time.perf_counter()
            events, parse_errors = [], 0
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        events.append(to_event(line, parser, Event))
                    except Exception:
                        parse_errors += 1
            row.update(stage="parsed", events=len(events), parse_errors=parse_errors,
                       load_parse_seconds=time.perf_counter() - started)
            update_peak(row)
            atomic_write(out, payload)
            started = time.perf_counter()
            findings = list(apply_rules(events, rules))
            observed: set[str] = set()
            for finding in findings:
                observed.update(finding_techniques(finding))
            row.update(stage="detected", findings=len(findings),
                       flagged_events=len({id(f.event) for f in findings}),
                       observed_techniques=sorted(observed),
                       detection_seconds=time.perf_counter() - started)
            update_peak(row)
            atomic_write(out, payload)
            started = time.perf_counter()
            chains = correlate(events, findings)
            row.update(stage="correlated", chain_count=len(chains),
                       chain_types=dict(sorted(Counter(getattr(c, "chain_type", "") for c in chains).items())),
                       correlation_seconds=time.perf_counter() - started)
            update_peak(row)
            atomic_write(out, payload)
            started = time.perf_counter()
            scenarios = infer(chains, findings)
            technique_hit = any(satisfies(source["technique_id"], value) for value in observed)
            row.update(stage="completed", scenario_count=len(scenarios),
                       scenario_techniques=sorted({t for s in scenarios for t in (getattr(s, "mitre_techniques", None) or [])}),
                       scenario_seconds=time.perf_counter() - started,
                       expected_technique_present=technique_hit,
                       dataset_status="HIT" if parse_errors == 0 and technique_hit else "MISS")
            update_peak(row)
            tracemalloc.stop()
            atomic_write(out, payload)
        except BaseException as exc:
            update_peak(row)
            if tracemalloc.is_tracing():
                tracemalloc.stop()
            row.update(stage="failed", dataset_status="ERROR", error=f"{type(exc).__name__}: {exc}")
            atomic_write(out, payload)
    hits = sum(row.get("dataset_status") == "HIT" for row in payload["datasets"])
    payload["summary"] = {
        "dataset_count": len(payload["datasets"]),
        "hits": hits,
        "misses_or_errors": len(payload["datasets"]) - hits,
        "path_label_dataset_hit_rate": hits / len(payload["datasets"]) if payload["datasets"] else 0.0,
        "wall_seconds": time.perf_counter() - overall,
    }
    payload["claim_boundary"] = {
        "event_level_ground_truth": "NOT_AVAILABLE",
        "detection_precision": "NOT_CLAIMED",
        "detection_recall": "NOT_CLAIMED",
        "false_positive_rate": "NOT_CLAIMED",
        "scenario_accuracy": "NOT_CLAIMED",
        "production_quality": "NOT_CLAIMED",
        "path_label_dataset_hit_rate_is_event_level_recall": False,
    }
    payload["status"] = "completed"
    atomic_write(out, payload)
    print(json.dumps(payload["summary"], sort_keys=True))
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product-repo", required=True)
    parser.add_argument("--binding", required=True)
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
