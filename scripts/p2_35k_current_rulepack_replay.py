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

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

ANALYSIS_ID = "p2-35k-current-rulepack-postchange-replay-v1"
SCHEMA = "breachscope.p2_35k_current_rulepack_postchange_replay.v1"


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
    h.update(f"blob {size}\0".encode("utf-8"))
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def global_lock_path() -> Path:
    return Path.home() / ".breachscope" / "canonical_locks" / "P2_35K_CURRENT_RULEPACK_REPLAY.lock"


def acquire_global_lock(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(f"analysis id already permanently locked: {path}") from exc
    try:
        os.write(
            fd,
            (
                json.dumps(
                    {
                        "analysis_id": ANALYSIS_ID,
                        "pid": os.getpid(),
                        "created_unix": time.time(),
                    }
                )
                + "\n"
            ).encode("utf-8"),
        )
    finally:
        os.close(fd)


def load_product(repo: Path):
    repo = repo.resolve()
    repo_text = str(repo)
    for name in tuple(sys.modules):
        if (
            name == "breachscope"
            or name.startswith("breachscope.")
            or name == "scripts"
            or name == "scripts.evaluate_external_holdout"
        ):
            sys.modules.pop(name, None)
    sys.path[:] = [entry for entry in sys.path if entry != repo_text]
    sys.path.insert(0, repo_text)

    import breachscope.analyzer as analyzer_module
    import breachscope.ingest as ingest_module
    import breachscope.rules as rules_module
    import breachscope.schemas as schemas_module
    import scripts.evaluate_external_holdout as holdout_module

    modules = (
        analyzer_module,
        ingest_module,
        rules_module,
        schemas_module,
        holdout_module,
    )
    for module in modules:
        module_path = Path(module.__file__).resolve()
        try:
            module_path.relative_to(repo)
        except ValueError as exc:
            raise RuntimeError(
                f"product module resolved outside frozen product repo: {module.__name__} -> {module_path}"
            ) from exc

    return (
        analyzer_module.apply_rules,
        ingest_module._extract_from_xml,
        rules_module.load_rules,
        schemas_module.Event,
        holdout_module.rules_tree_hash,
    )


def verify_product(repo: Path, contract: dict[str, Any], rules_tree_hash, load_rules) -> dict[str, Any]:
    frozen = contract["frozen_product"]
    head = git(repo, "rev-parse", "HEAD")
    dirty = git(repo, "status", "--porcelain", "-uall")
    rule_hash, rule_files = rules_tree_hash(repo / "rules")
    rules = load_rules(repo / "rules")
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
        "rule_count": len(rules),
        "rule_file_count": rule_files,
    }


def to_event(xml: str, parser, Event):
    row = parser(xml)
    if not isinstance(row, dict):
        raise ValueError("product XML parser returned non-mapping")
    keys = ("timestamp", "host", "source", "event_id", "level", "user", "command_line", "raw")
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


def verify_attack_sources(attack_dir: Path, contract: dict[str, Any]) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    expected = {row["filename"] for row in contract["attack_replay"]["datasets"]}
    actual = {p.name for p in attack_dir.iterdir() if p.is_file()}
    unexpected = sorted(actual - expected)
    if unexpected:
        raise RuntimeError(f"unexpected attack source files: {unexpected}")
    for source in contract["attack_replay"]["datasets"]:
        path = attack_dir / source["filename"]
        if not path.is_file():
            raise RuntimeError(f"missing attack source: {source['filename']}")
        row = {
            "dataset_id": source["dataset_id"],
            "filename": source["filename"],
            "size_bytes": path.stat().st_size,
            "git_blob_sha1": git_blob_sha1(path),
            "sha256": sha256(path),
        }
        row["size_match"] = row["size_bytes"] == source["size_bytes"]
        row["git_blob_match"] = row["git_blob_sha1"] == source["git_blob_sha1"]
        row["sha256_match"] = row["sha256"] == source["sha256"]
        if not all((row["size_match"], row["git_blob_match"], row["sha256_match"])):
            raise RuntimeError(f"attack source identity mismatch: {source['dataset_id']}")
        verified.append(row)
    return verified


def verify_benign_sources(benign_dir: Path, contract: dict[str, Any]) -> list[dict[str, Any]]:
    files = contract["benign_replay"]["files"]
    expected = {row["filename"] for row in files if row["available"]}
    actual = {p.name for p in benign_dir.iterdir() if p.is_file()}
    unexpected = sorted(actual - expected - {"identity.json"})
    if unexpected:
        raise RuntimeError(f"unexpected benign source files: {unexpected}")
    verified: list[dict[str, Any]] = []
    for source in files:
        if not source["available"]:
            continue
        path = benign_dir / source["filename"]
        if not path.is_file():
            raise RuntimeError(f"missing benign source: {source['filename']}")
        row = {
            "channel": source["channel"],
            "filename": source["filename"],
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        row["size_match"] = row["size_bytes"] == source["size_bytes"]
        row["sha256_match"] = row["sha256"] == source["sha256"]
        if not row["size_match"] or not row["sha256_match"]:
            raise RuntimeError(f"benign source identity mismatch: {source['filename']}")
        verified.append(row)
    return verified


def finding_techniques(finding: Any) -> list[str]:
    values = list(getattr(finding, "mitre_techniques", None) or [])
    primary = getattr(finding, "mitre_technique", None)
    if primary:
        values.append(primary)
    return sorted(
        {
            str(value).strip().upper()
            for value in values
            if str(value or "").strip()
        }
    )


def run(args: argparse.Namespace) -> int:
    repo = Path(args.product_repo).resolve()
    contract_path = Path(args.contract).resolve()
    attack_dir = Path(args.attack_dir).resolve()
    benign_dir = Path(args.benign_dir).resolve()
    out = Path(args.out).resolve()
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))

    if contract["analysis_id"] != ANALYSIS_ID:
        raise RuntimeError("analysis id mismatch")

    lock = global_lock_path()
    acquire_global_lock(lock)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "analysis_id": ANALYSIS_ID,
        "status": "started",
        "contract_sha256": sha256(contract_path),
        "runner_sha256": text_sha256(Path(__file__).resolve()),
        "global_lock_path": str(lock),
        "attack_replay": {"datasets": []},
        "benign_replay": {"channels": []},
    }
    atomic_write(out, payload)

    try:
        if payload["runner_sha256"] != contract["runner"]["sha256"]:
            raise RuntimeError("runner SHA mismatch")

        apply_rules, parser, load_rules, Event, rules_tree_hash = load_product(repo)
        payload["frozen_product"] = verify_product(repo, contract, rules_tree_hash, load_rules)
        rules = load_rules(repo / "rules")

        payload["source_verification"] = {
            "attack": verify_attack_sources(attack_dir, contract),
            "benign": verify_benign_sources(benign_dir, contract),
        }
        payload["status"] = "sources_verified"
        atomic_write(out, payload)

        attack_hits = attack_misses = attack_errors = 0
        for source in contract["attack_replay"]["datasets"]:
            row: dict[str, Any] = {
                "dataset_id": source["dataset_id"],
                "scenario_label": source["scenario_label"],
                "filename": source["filename"],
                "stage": "started",
            }
            payload["attack_replay"]["datasets"].append(row)
            atomic_write(out, payload)
            try:
                events, raw_records, parse_errors = load_evtx(
                    attack_dir / source["filename"], parser, Event
                )
                if not events:
                    raise RuntimeError("fixture parsed zero events")
                findings = list(apply_rules(events, rules))
                rule_counts = Counter(str(getattr(f, "rule_id", "") or "") for f in findings)
                technique_counts: Counter[str] = Counter()
                for finding in findings:
                    technique_counts.update(finding_techniques(finding))
                status = "HIT" if findings else "MISS"
                if status == "HIT":
                    attack_hits += 1
                else:
                    attack_misses += 1
                row.update(
                    stage="completed",
                    fixture_status=status,
                    raw_records=raw_records,
                    parsed_events=len(events),
                    parse_errors=parse_errors,
                    findings=len(findings),
                    flagged_events=len({id(f.event) for f in findings}),
                    findings_by_rule=dict(sorted(rule_counts.items())),
                    findings_by_technique=dict(sorted(technique_counts.items())),
                )
                atomic_write(out, payload)
            except BaseException as exc:
                attack_errors += 1
                row.update(
                    stage="failed",
                    fixture_status="ERROR",
                    error=f"{type(exc).__name__}: {exc}",
                )
                atomic_write(out, payload)

        payload["attack_replay"]["summary"] = {
            "fixture_count": len(contract["attack_replay"]["datasets"]),
            "hits": attack_hits,
            "misses": attack_misses,
            "errors": attack_errors,
            "fixture_hit_rate": attack_hits / len(contract["attack_replay"]["datasets"]),
        }

        all_benign_events: list[Any] = []
        event_channels: dict[int, str] = {}
        total_raw = 0
        total_errors = 0
        for source in contract["benign_replay"]["files"]:
            if not source["available"]:
                continue
            events, raw_records, parse_errors = load_evtx(
                benign_dir / source["filename"], parser, Event
            )
            channel_row = {
                "channel": source["channel"],
                "filename": source["filename"],
                "raw_records": raw_records,
                "parsed_events": len(events),
                "parse_errors": parse_errors,
            }
            payload["benign_replay"]["channels"].append(channel_row)
            total_raw += raw_records
            total_errors += parse_errors
            for event in events:
                event_channels[id(event)] = source["channel"]
            all_benign_events.extend(events)
            atomic_write(out, payload)

        if not all_benign_events:
            raise RuntimeError("all benign EVTX files parsed zero events")

        benign_findings = list(apply_rules(all_benign_events, rules))
        benign_flagged_ids = {id(f.event) for f in benign_findings}
        findings_by_rule = Counter(str(getattr(f, "rule_id", "") or "") for f in benign_findings)
        findings_by_channel = Counter(
            event_channels.get(id(f.event), "UNKNOWN") for f in benign_findings
        )
        fraction = len(benign_flagged_ids) / len(all_benign_events)
        payload["benign_replay"]["summary"] = {
            "raw_records": total_raw,
            "parsed_events": len(all_benign_events),
            "parse_errors": total_errors,
            "findings": len(benign_findings),
            "flagged_events": len(benign_flagged_ids),
            "observed_source_intent_benign_flagged_event_fraction": fraction,
            "observed_source_intent_benign_flagged_event_percent": fraction * 100,
            "findings_by_rule": dict(sorted(findings_by_rule.items())),
            "findings_by_channel": dict(sorted(findings_by_channel.items())),
        }

        payload["claim_boundary"] = {
            "source_class": "REPLAY_OF_PREVIOUSLY_OBSERVED_EXACT_BYTES",
            "fresh_external_source": False,
            "independent_holdout": False,
            "attack_fixture_hit_rate_is_event_level_recall": False,
            "event_level_attack_ground_truth": "NOT_AVAILABLE",
            "event_level_benign_ground_truth": "NOT_AVAILABLE",
            "confirmed_false_positive_rate": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "fresh_current_rulepack_performance": "NOT_CLAIMED",
        }
        payload["status"] = "completed"
        atomic_write(out, payload)
        print(
            json.dumps(
                {
                    "attack": payload["attack_replay"]["summary"],
                    "benign": payload["benign_replay"]["summary"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    except BaseException as exc:
        payload.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        atomic_write(out, payload)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run P2-35J post-change replay revalidation on exact previously observed sources."
    )
    parser.add_argument("--product-repo", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--attack-dir", required=True)
    parser.add_argument("--benign-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
