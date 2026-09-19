#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "breachscope.p2_24c_ask92_benign_one_pass.v1"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


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


def parse_upstream_timestamp(xml: str) -> tuple[str | None, datetime | None]:
    root = ET.fromstring(xml)
    elem = root.find("./e:System/e:TimeCreated", NS)
    if elem is None:
        return None, None
    raw = elem.get("SystemTime")
    if not raw:
        return None, None
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    return raw, parsed


def to_event(xml: str, parser, Event):
    row = parser(xml)
    if not isinstance(row, dict):
        raise ValueError("product XML parser returned non-mapping")
    keys = ("timestamp", "host", "source", "event_id", "level", "user", "command_line", "raw")
    return Event(**{key: row.get(key) for key in keys})


def load_and_eligibility_check(path: Path, parser, Event, cutoff: datetime) -> tuple[list[Any], dict[str, Any]]:
    from Evtx.Evtx import Evtx

    events: list[Any] = []
    record_count = 0
    product_parse_errors = 0
    missing_timestamps = 0
    timestamp_parse_errors = 0
    over_cutoff = 0
    min_time: datetime | None = None
    max_time: datetime | None = None

    with Evtx(str(path)) as log:
        for record in log.records():
            record_count += 1
            try:
                xml = record.xml()
            except Exception:
                product_parse_errors += 1
                continue

            try:
                raw_ts, parsed_ts = parse_upstream_timestamp(xml)
                if raw_ts is None or parsed_ts is None:
                    missing_timestamps += 1
                else:
                    min_time = parsed_ts if min_time is None or parsed_ts < min_time else min_time
                    max_time = parsed_ts if max_time is None or parsed_ts > max_time else max_time
                    if parsed_ts > cutoff:
                        over_cutoff += 1
            except Exception:
                timestamp_parse_errors += 1

            try:
                events.append(to_event(xml, parser, Event))
            except Exception:
                product_parse_errors += 1

    eligibility = {
        "raw_record_count": record_count,
        "parsed_events": len(events),
        "product_parse_errors": product_parse_errors,
        "missing_timestamps": missing_timestamps,
        "timestamp_parse_errors": timestamp_parse_errors,
        "events_after_strict_cutoff": over_cutoff,
        "min_timestamp_naive": min_time.isoformat() if min_time else None,
        "max_timestamp_naive": max_time.isoformat() if max_time else None,
        "strict_cutoff_naive": cutoff.isoformat(),
        "upstream_timestamp_interpretation": "datetime.fromisoformat(SystemTime.replace('Z','+00:00')).replace(tzinfo=None)",
    }
    eligibility["eligible"] = (
        record_count > 0
        and len(events) == record_count
        and product_parse_errors == 0
        and missing_timestamps == 0
        and timestamp_parse_errors == 0
        and over_cutoff == 0
    )
    return events, eligibility


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
        payload["frozen_product"] = verify_product(product_repo, contract, rules_tree_hash, load_rules)
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

        cutoff = datetime.fromisoformat(contract["label_eligibility"]["strict_cutoff_naive"])
        started = time.perf_counter()
        events, eligibility = load_and_eligibility_check(source, parser, Event, cutoff)
        eligibility["seconds"] = time.perf_counter() - started
        payload["label_eligibility"] = eligibility

        if not eligibility["eligible"]:
            payload["measurement"] = {
                "status": "NOT_MEASURED",
                "reason": "BENIGN_LABEL_OR_PARSE_CONTRACT_FAILED",
            }
            payload["status"] = "failed"
            atomic_write(out, payload)
            return 4

        payload["status"] = "label_eligibility_passed"
        atomic_write(out, payload)

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
            "source_label": "benign_by_upstream_collection_intent_and_strict_timestamp_gate",
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
            "source_intent_label_not_event_level_manual_adjudication": True,
            "single_public_sysmon_export": True,
            "representative_production_population": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
            "statistical_confidence_interval": "NOT_CLAIMED",
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
    parser = argparse.ArgumentParser(description="Run the preregistered P2-24C ASK92 benign Sysmon one-pass measurement.")
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
