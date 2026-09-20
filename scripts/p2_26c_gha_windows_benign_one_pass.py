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
    temp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temp, path)


def acquire_permanent_lock(path: Path, analysis_id: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(f"one-pass lock already exists: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "analysis_id": analysis_id,
                "pid": os.getpid(),
                "created_unix": time.time(),
            },
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


def verify_product(
    product_repo: Path,
    contract: dict[str, Any],
    rules_tree_hash,
    load_rules,
) -> dict[str, Any]:
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
    keys = (
        "timestamp",
        "host",
        "source",
        "event_id",
        "level",
        "user",
        "command_line",
        "raw",
    )
    return Event(**{key: row.get(key) for key in keys})


def load_evtx(path: Path, parser, Event) -> tuple[list[Any], int, int]:
    from Evtx.Evtx import Evtx

    events: list[Any] = []
    raw_records = 0
    parse_errors = 0
    with Evtx(str(path)) as log:
        for record in log.records():
            raw_records += 1
            try:
                events.append(to_event(record.xml(), parser, Event))
            except Exception:
                parse_errors += 1
    return events, raw_records, parse_errors


def verify_sources(data_dir: Path, contract: dict[str, Any]) -> list[dict[str, Any]]:
    expected_names = {row["filename"] for row in contract["source_identity"]["files"]}
    actual_names = {path.name for path in data_dir.iterdir() if path.is_file()}
    unexpected = sorted(actual_names - expected_names - {"identity.json"})
    if unexpected:
        raise RuntimeError(f"unexpected files in source directory: {unexpected}")

    verified: list[dict[str, Any]] = []
    for source in contract["source_identity"]["files"]:
        if not source["available"]:
            continue
        path = data_dir / source["filename"]
        if not path.is_file():
            raise RuntimeError(f"missing source file: {source['filename']}")
        actual = {
            "channel": source["channel"],
            "filename": source["filename"],
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        actual["size_match"] = actual["size_bytes"] == source["size_bytes"]
        actual["sha256_match"] = actual["sha256"] == source["sha256"]
        if not actual["size_match"] or not actual["sha256_match"]:
            raise RuntimeError(f"source identity mismatch: {source['filename']}")
        verified.append(actual)
    return verified


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
    print(
        json.dumps(
            {
                "status": "PRECHECK_PASS",
                **frozen,
                "runner_sha256": actual_runner,
            },
            sort_keys=True,
        )
    )
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

        apply_rules, parser, load_rules, Event, rules_tree_hash = load_product(
            product_repo
        )
        payload["frozen_product"] = verify_product(
            product_repo,
            contract,
            rules_tree_hash,
            load_rules,
        )
        rules = load_rules(product_repo / "rules")

        payload["source_verification"] = verify_sources(data_dir, contract)
        payload["status"] = "sources_verified"
        atomic_write(out, payload)

        all_events: list[Any] = []
        event_channels: dict[int, str] = {}
        total_raw_records = 0
        total_parse_errors = 0

        for source in contract["source_identity"]["files"]:
            if not source["available"]:
                continue
            path = data_dir / source["filename"]
            started = time.perf_counter()
            events, raw_records, parse_errors = load_evtx(path, parser, Event)
            channel_row = {
                "channel": source["channel"],
                "filename": source["filename"],
                "raw_records": raw_records,
                "parsed_events": len(events),
                "parse_errors": parse_errors,
                "parse_seconds": time.perf_counter() - started,
            }
            payload["channels"].append(channel_row)
            total_raw_records += raw_records
            total_parse_errors += parse_errors
            for event in events:
                event_channels[id(event)] = source["channel"]
            all_events.extend(events)
            atomic_write(out, payload)

        if not all_events:
            raise RuntimeError("all bound EVTX files parsed zero events")

        payload["status"] = "parsed"
        payload["parse_summary"] = {
            "raw_records": total_raw_records,
            "parsed_events": len(all_events),
            "parse_errors": total_parse_errors,
        }
        atomic_write(out, payload)

        started = time.perf_counter()
        findings = list(apply_rules(all_events, rules))
        flagged_event_ids = {id(finding.event) for finding in findings}
        findings_by_rule = Counter(
            str(getattr(finding, "rule_id", "") or "") for finding in findings
        )
        findings_by_channel = Counter(
            event_channels.get(id(finding.event), "UNKNOWN") for finding in findings
        )
        flagged_events_by_channel = Counter(
            event_channels.get(event_id, "UNKNOWN") for event_id in flagged_event_ids
        )

        flagged_events = len(flagged_event_ids)
        fraction = flagged_events / len(all_events)
        payload["measurement"] = {
            "status": "MEASURED",
            "source_label": "source_intent_benign_ephemeral_ci_baseline",
            "parsed_events": len(all_events),
            "parse_errors": total_parse_errors,
            "flagged_events": flagged_events,
            "findings": len(findings),
            "observed_source_intent_benign_flagged_event_fraction": fraction,
            "observed_source_intent_benign_flagged_event_percent": fraction * 100,
            "rules_evaluated": len(rules),
            "findings_by_rule": dict(sorted(findings_by_rule.items())),
            "findings_by_channel": dict(sorted(findings_by_channel.items())),
            "flagged_events_by_channel": dict(
                sorted(flagged_events_by_channel.items())
            ),
            "detection_seconds": time.perf_counter() - started,
        }
        payload["claim_boundary"] = {
            "event_level_benign_ground_truth": "NOT_AVAILABLE",
            "confirmed_false_positive_rate": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "representative_production_population": "NOT_CLAIMED",
            "measured_value_is_production_fpr": False,
        }
        payload["status"] = "completed"
        atomic_write(out, payload)
        print(json.dumps(payload["measurement"], sort_keys=True))
        return 0
    except BaseException as exc:
        payload.update(
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
        )
        payload.setdefault("measurement", {"status": "NOT_MEASURED"})
        atomic_write(out, payload)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the preregistered P2-26C GitHub Actions benign EVTX one-pass measurement."
    )
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
