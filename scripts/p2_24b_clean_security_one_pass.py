#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "breachscope.p2_24b_clean_security_one_pass.v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def git_blob_sha1(path: Path) -> str:
    size = path.stat().st_size
    h = hashlib.sha1()
    h.update(f"blob {size}\0".encode())
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
        json.dump({"analysis_id": analysis_id, "pid": os.getpid(), "created_unix": time.time()}, handle)


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


def preflight(args: argparse.Namespace) -> int:
    product_repo = Path(args.product_repo).resolve()
    contract_path = Path(args.contract).resolve()
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    apply_rules, parser, load_rules, Event, rules_tree_hash = load_product(product_repo)
    del apply_rules, parser, Event
    frozen = verify_product(product_repo, contract, rules_tree_hash, load_rules)
    actual_runner = text_sha256(Path(__file__).resolve())
    if actual_runner != contract["runner"]["sha256"]:
        raise RuntimeError("runner SHA mismatch")
    print(json.dumps({"status": "PRECHECK_PASS", **frozen, "runner_sha256": actual_runner}, sort_keys=True))
    return 0


def run(args: argparse.Namespace) -> int:
    product_repo = Path(args.product_repo).resolve()
    contract_path = Path(args.contract).resolve()
    source = Path(args.source).resolve()
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
    }
    atomic_write(out, payload)

    try:
        if payload["runner_sha256"] != contract["runner"]["sha256"]:
            raise RuntimeError("runner SHA mismatch")

        apply_rules, parser, load_rules, Event, rules_tree_hash = load_product(product_repo)
        payload["frozen_product"] = verify_product(
            product_repo, contract, rules_tree_hash, load_rules
        )
        rules = load_rules(product_repo / "rules")

        bound = contract["source"]
        actual = {
            "size_bytes": source.stat().st_size,
            "git_blob_sha1": git_blob_sha1(source),
            "sha256": sha256(source),
        }
        actual["size_match"] = actual["size_bytes"] == bound["size_bytes"]
        actual["git_blob_match"] = actual["git_blob_sha1"] == bound["git_blob_sha1"]
        actual["sha256_match"] = actual["sha256"] == bound["sha256"]
        payload["source_verification"] = actual
        if not all((actual["size_match"], actual["git_blob_match"], actual["sha256_match"])):
            raise RuntimeError("source identity mismatch")
        payload["status"] = "source_verified"
        atomic_write(out, payload)

        started = time.perf_counter()
        events, parse_errors = load_evtx(source, parser, Event)
        payload["parse"] = {
            "parsed_events": len(events),
            "parse_errors": parse_errors,
            "seconds": time.perf_counter() - started,
        }
        expected = contract["scoring"]["expected_parsed_events"]
        if len(events) != expected or parse_errors != 0:
            payload["measurement"] = {
                "status": "NOT_MEASURED",
                "reason": "PARSE_CONTRACT_MISMATCH",
            }
            payload["status"] = "failed"
            atomic_write(out, payload)
            return 4

        started = time.perf_counter()
        findings = list(apply_rules(events, rules))
        flagged_ids = {id(finding.event) for finding in findings}
        per_rule = Counter(str(getattr(finding, "rule_id", "") or "") for finding in findings)
        per_technique = Counter(
            str(getattr(finding, "mitre_technique", "") or "") for finding in findings
        )
        flagged_events = len(flagged_ids)
        fpr = flagged_events / len(events) if events else None
        payload["measurement"] = {
            "status": "MEASURED",
            "source_label": "benign_by_upstream_explicit_clean_fixture_description",
            "parsed_benign_events": len(events),
            "flagged_benign_events": flagged_events,
            "findings": len(findings),
            "false_positive_rate": fpr,
            "false_positive_percent": fpr * 100 if fpr is not None else None,
            "rules_evaluated": len(rules),
            "findings_by_rule": dict(sorted(per_rule.items())),
            "findings_by_primary_technique": dict(sorted(per_technique.items())),
            "detection_seconds": time.perf_counter() - started,
        }
        payload["claim_boundary"] = {
            "corpus_representativeness": "VERY_LIMITED_7_RECORD_FIXTURE",
            "event_level_manual_adjudication": False,
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
            "representative_production_population": "NOT_CLAIMED",
        }
        payload["status"] = "completed"
        atomic_write(out, payload)
        print(json.dumps(payload["measurement"], sort_keys=True))
        return 0
    except BaseException as exc:
        payload.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        payload.setdefault("measurement", {"status": "NOT_MEASURED"})
        atomic_write(out, payload)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the preregistered P2-24B clean EVTX one-pass measurement.")
    parser.add_argument("--product-repo", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--source")
    parser.add_argument("--out")
    parser.add_argument("--lock")
    args = parser.parse_args()
    if args.preflight:
        return preflight(args)
    if not all((args.source, args.out, args.lock)):
        parser.error("--source, --out and --lock are required for a run")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
