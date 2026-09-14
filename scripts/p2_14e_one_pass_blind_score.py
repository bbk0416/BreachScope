#!/usr/bin/env python3
"""P2-14E final blind holdout one-pass operational scorer.

This runner intentionally does not consume event-level labels and therefore does
not compute precision, recall, false-positive rate, accuracy, or a confusion
matrix. It executes the frozen BreachScope detector exactly once after all
identity and corpus checks have passed.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import asdict, is_dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

import yaml

FROZEN_DETECTOR_COMMIT = "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
FROZEN_RULES_TREE_SHA256 = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
FROZEN_RULE_FILE_COUNT = 4
FROZEN_RULE_COUNT = 66
BOUND_ARCHIVE_SIZE = 6053609
BOUND_ARCHIVE_SHA256 = "99e0ca3dae2f7582d9757dfe41b4f1fb149b197fe3bb751613760087f2d68594"
BOUND_PATH_MANIFEST_SHA256 = "33ace64e0154e14698c462ae185c60acee54a3ee88023d0cb792d86cf76dcb5a"
BOUND_EVTX_FILE_COUNT = 278
BOUND_RECORD_COUNT = 37364
RESULT_SCHEMA = "breachscope.p2_14e_final_blind_one_pass_result.v1"
CONTROL_ROOT = Path(__file__).resolve().parents[1]


class ScoreError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def _rules_tree_hash(rules_dir: Path) -> tuple[str, int]:
    files = sorted(
        p for p in rules_dir.rglob("*")
        if p.is_file() and p.suffix.casefold() in {".yml", ".yaml"}
    )
    h = hashlib.sha256()
    for path in files:
        rel = path.relative_to(rules_dir).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        canonical = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        h.update(hashlib.sha256(canonical).hexdigest().encode("ascii"))
        h.update(b"\0")
    return h.hexdigest(), len(files)


def _safe_member_path(name: str) -> PurePosixPath:
    rel = PurePosixPath(name)
    if rel.is_absolute():
        raise ScoreError(f"unsafe absolute archive path: {name}")
    parts = tuple(part for part in rel.parts if part not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        raise ScoreError(f"unsafe archive path: {name}")
    return PurePosixPath(*parts)


def verify_and_extract_archive(archive_path: Path, corpus_root: Path) -> list[Path]:
    if archive_path.stat().st_size != BOUND_ARCHIVE_SIZE:
        raise ScoreError("archive size mismatch")
    if _sha256_path(archive_path) != BOUND_ARCHIVE_SHA256:
        raise ScoreError("archive SHA-256 mismatch")

    with tarfile.open(archive_path, "r:gz") as archive:
        evtx_members = [
            member for member in archive.getmembers()
            if member.isfile() and member.name.casefold().endswith(".evtx")
        ]
        paths = sorted(member.name for member in evtx_members)
        manifest = ("\n".join(paths) + "\n").encode("utf-8")
        if len(paths) != BOUND_EVTX_FILE_COUNT:
            raise ScoreError(f"EVTX count mismatch: {len(paths)}")
        if _sha256_bytes(manifest) != BOUND_PATH_MANIFEST_SHA256:
            raise ScoreError("EVTX path manifest SHA-256 mismatch")

        root = corpus_root.resolve()
        extracted: list[Path] = []
        for member in sorted(evtx_members, key=lambda item: item.name):
            rel = _safe_member_path(member.name)
            target = (root / Path(*rel.parts)).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ScoreError(f"archive path escapes corpus root: {member.name}") from exc
            source = archive.extractfile(member)
            if source is None:
                raise ScoreError(f"could not read archive member: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            extracted.append(target)
    return extracted


def _activate_frozen_detector(detector_root: Path) -> None:
    detector_root = detector_root.resolve()
    current_root = CONTROL_ROOT.resolve()
    cleaned = []
    for entry in sys.path:
        try:
            resolved = Path(entry or os.getcwd()).resolve()
        except OSError:
            cleaned.append(entry)
            continue
        if resolved != current_root:
            cleaned.append(entry)
    sys.path[:] = [str(detector_root), *cleaned]


def _get(value: Any, key: str, default: Any = "") -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def event_identity_payload(event: Any) -> dict[str, str]:
    raw = _get(event, "raw", {})
    if not isinstance(raw, Mapping):
        raw = {}
    canonical = raw.get("canonical")
    if not isinstance(canonical, Mapping):
        canonical = {}
    system = raw.get("system")
    if not isinstance(system, Mapping):
        system = {}

    def first(name: str, *aliases: str) -> str:
        direct = _get(event, name, "")
        if direct not in (None, ""):
            return str(direct)
        for source in (canonical, raw):
            for candidate in (name, *aliases):
                item = source.get(candidate)
                if item not in (None, ""):
                    return str(item)
        return ""

    def system_first(*names: str) -> str:
        for name in names:
            item = system.get(name)
            if item not in (None, ""):
                return str(item)
        return ""

    payload = {
        "timestamp": first("timestamp", "time_created", "TimeCreated"),
        "host": first("host", "computer", "Computer"),
        "source": first("source", "provider", "ProviderName"),
        "event_id": first("event_id", "EventID", "eventid"),
        "user": first("user", "User", "SubjectUserName"),
        "command_line": first("command_line", "CommandLine", "ProcessCommandLine"),
    }
    channel = first("channel", "Channel") or system_first("Channel", "channel")
    event_record_id = (
        first("event_record_id", "EventRecordID", "record_id")
        or system_first("EventRecordID", "event_record_id", "record_id")
    )
    if channel:
        payload["channel"] = channel
    if event_record_id:
        payload["event_record_id"] = event_record_id
    return payload


def _record_to_event(raw: dict[str, Any]):
    from breachscope.schemas import Event

    identity = event_identity_payload(raw)
    params = inspect.signature(Event).parameters
    event_raw = raw.get("raw")
    if not isinstance(event_raw, dict):
        event_raw = raw
    candidate = {
        "timestamp": identity["timestamp"],
        "host": identity["host"],
        "source": identity["source"],
        "event_id": identity["event_id"],
        "user": identity["user"],
        "command_line": identity["command_line"],
        "raw": event_raw,
    }
    return Event(**{key: value for key, value in candidate.items() if key in params})


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ScoreError(f"invalid converted JSONL {path}:{line_no}") from exc
            if not isinstance(value, dict):
                raise ScoreError(f"converted JSONL row is not an object: {path}:{line_no}")
            yield value


def parse_all_evtx(evtx_files: list[Path], corpus_root: Path):
    from breachscope.ingest import convert_evtx_dir

    events = []
    metadata_by_object: dict[int, dict[str, Any]] = {}
    per_file_record_counts: dict[str, int] = {}

    for evtx in evtx_files:
        rel = evtx.relative_to(corpus_root).as_posix()
        temp_root = Path(tempfile.mkdtemp(prefix="p2-14e-evtx-"))
        try:
            input_dir = temp_root / "input"
            input_dir.mkdir()
            local = input_dir / evtx.name
            try:
                os.link(evtx, local)
            except OSError:
                shutil.copy2(evtx, local)
            converted = convert_evtx_dir(input_dir)
            if converted is None:
                raise ScoreError(f"EVTX conversion returned no output: {rel}")
            jsonl_files = sorted(Path(converted).rglob("*.jsonl"))
            if not jsonl_files:
                raise ScoreError(f"EVTX conversion produced no JSONL: {rel}")
            count = 0
            for jsonl in jsonl_files:
                for raw in _iter_jsonl(jsonl):
                    count += 1
                    event = _record_to_event(raw)
                    metadata_by_object[id(event)] = {
                        "source_file": rel,
                        "record_index": count,
                        "identity": event_identity_payload(event),
                        "raw": raw,
                    }
                    events.append(event)
            if count == 0:
                raise ScoreError(f"zero-record EVTX file: {rel}")
            per_file_record_counts[rel] = count
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

    if len(events) != BOUND_RECORD_COUNT:
        raise ScoreError(f"record count mismatch: expected={BOUND_RECORD_COUNT} actual={len(events)}")
    return events, metadata_by_object, per_file_record_counts


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def run_score(detector_root: Path, archive_path: Path, out_path: Path) -> dict[str, Any]:
    detector_root = detector_root.resolve()
    detector_commit = _git(detector_root, "rev-parse", "HEAD")
    if detector_commit != FROZEN_DETECTOR_COMMIT:
        raise ScoreError(f"detector commit mismatch: {detector_commit}")
    if _git(detector_root, "status", "--porcelain", "-uall"):
        raise ScoreError("frozen detector working tree is not clean")

    rules_dir = detector_root / "rules"
    rules_hash, rule_file_count = _rules_tree_hash(rules_dir)
    if rules_hash != FROZEN_RULES_TREE_SHA256:
        raise ScoreError("rules tree SHA-256 mismatch")
    if rule_file_count != FROZEN_RULE_FILE_COUNT:
        raise ScoreError("rule file count mismatch")

    _activate_frozen_detector(detector_root)
    from breachscope.analyzer import apply_rules
    from breachscope.rules import load_rules

    rules = load_rules(rules_dir)
    if len(rules) != FROZEN_RULE_COUNT:
        raise ScoreError(f"loaded rule count mismatch: {len(rules)}")

    temp_root = Path(tempfile.mkdtemp(prefix="p2-14e-corpus-"))
    try:
        corpus_root = temp_root / "corpus"
        corpus_root.mkdir()
        evtx_files = verify_and_extract_archive(archive_path, corpus_root)
        events, meta_by_object, per_file_record_counts = parse_all_evtx(evtx_files, corpus_root)

        # This is the single detector invocation for the canonical one-pass run.
        start = time.perf_counter()
        findings = list(apply_rules(events, rules))
        runtime_seconds = time.perf_counter() - start

        findings_by_rule = Counter()
        flagged_by_rule: dict[str, set[tuple[str, int]]] = defaultdict(set)
        per_file_finding_counts = Counter()
        flagged: dict[tuple[str, int], dict[str, Any]] = {}

        for finding in findings:
            event = getattr(finding, "event", None)
            metadata = meta_by_object.get(id(event))
            if metadata is None:
                raise ScoreError("finding could not be mapped to a parsed event")
            key = (metadata["source_file"], int(metadata["record_index"]))
            rule_id = str(getattr(finding, "rule_id", "") or "")
            if not rule_id:
                raise ScoreError("finding without rule_id")
            findings_by_rule[rule_id] += 1
            flagged_by_rule[rule_id].add(key)
            per_file_finding_counts[metadata["source_file"]] += 1
            entry = flagged.setdefault(
                key,
                {
                    "source_file": metadata["source_file"],
                    "record_index": metadata["record_index"],
                    "identity": metadata["identity"],
                    "raw": _jsonable(metadata["raw"]),
                    "findings": [],
                },
            )
            entry["findings"].append(
                {
                    "rule_id": rule_id,
                    "rule_name": str(getattr(finding, "rule_name", "") or ""),
                    "severity": str(getattr(finding, "severity", "") or ""),
                    "mitre_technique": getattr(finding, "mitre_technique", None),
                    "mitre_techniques": list(getattr(finding, "mitre_techniques", []) or []),
                    "matched_value": getattr(finding, "matched_value", None),
                    "matched_context": getattr(finding, "matched_context", None),
                }
            )

        flagged_events = [flagged[key] for key in sorted(flagged)]
        payload: dict[str, Any] = {
            "schema": RESULT_SCHEMA,
            "phase": "P2-14E",
            "status": "CANONICAL_ONE_PASS_SCORING_COMPLETED",
            "corpus_identity": {
                "repository": "sbousseaden/EVTX-ATTACK-SAMPLES",
                "source_commit": "4ceed2f4706daf601c212a8f91c113dd85349a2c",
                "archive_size_bytes": BOUND_ARCHIVE_SIZE,
                "archive_sha256": BOUND_ARCHIVE_SHA256,
                "evtx_file_count": BOUND_EVTX_FILE_COUNT,
                "path_manifest_sha256": BOUND_PATH_MANIFEST_SHA256,
            },
            "detector_identity": {
                "repo_commit": FROZEN_DETECTOR_COMMIT,
                "rules_tree_sha256": FROZEN_RULES_TREE_SHA256,
                "rule_file_count": FROZEN_RULE_FILE_COUNT,
                "rule_count": FROZEN_RULE_COUNT,
            },
            "total_records": BOUND_RECORD_COUNT,
            "parsed_records": len(events),
            "parse_errors": 0,
            "findings": len(findings),
            "flagged_events": len(flagged_events),
            "detected_rule_count": len(findings_by_rule),
            "findings_by_rule": dict(sorted(findings_by_rule.items())),
            "flagged_events_by_rule": {
                rule_id: len(keys) for rule_id, keys in sorted(flagged_by_rule.items())
            },
            "per_file_record_counts": dict(sorted(per_file_record_counts.items())),
            "per_file_finding_counts": {
                name: int(per_file_finding_counts.get(name, 0))
                for name in sorted(per_file_record_counts)
            },
            "flagged_event_metadata": flagged_events,
            "runtime_seconds": runtime_seconds,
            "claim_boundary": {
                "event_level_ground_truth": "NOT_AVAILABLE",
                "production_accuracy": "NOT_CLAIMED",
                "production_detection_rate": "NOT_CLAIMED",
                "production_precision": "NOT_CLAIMED",
                "production_recall": "NOT_CLAIMED",
                "production_false_positive_rate": "NOT_CLAIMED",
                "finding_count_is_not_recall": True,
                "flagged_event_fraction_is_not_false_positive_rate": True,
            },
            "canonical_hash_contract": "sha256 of deterministic JSON payload excluding canonical_result_sha256",
        }
        canonical_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        payload["canonical_result_sha256"] = hashlib.sha256(canonical_bytes).hexdigest()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return payload
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="P2-14E one-pass final blind operational scorer")
    ap.add_argument("--detector-root", required=True)
    ap.add_argument("--archive", required=True)
    ap.add_argument("--out", required=True)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = run_score(Path(args.detector_root), Path(args.archive), Path(args.out))
    except ScoreError as exc:
        print(f"P2-14E ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"],
        "findings": result["findings"],
        "flagged_events": result["flagged_events"],
        "canonical_result_sha256": result["canonical_result_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
