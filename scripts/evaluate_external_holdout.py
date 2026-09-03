#!/usr/bin/env python3
"""External/blind holdout evaluator for BreachScope.

This tool is deliberately separate from evaluate_detection_corpus.py.

Protocol:
1. freeze  - freeze the exact repository/rule state.
2. index   - ingest/hash the external corpus WITHOUT running detection rules.
3. label   - performed outside this tool, ideally by an independent labeler.
4. score   - verify corpus/rule/label hashes, run detection, and measure outcomes.

The tool can enforce hashes and recorded self-attestations. It cannot prove that
a corpus was truly independent or that a human labeler was actually blinded.
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
import tempfile
import time
import tracemalloc
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

SCHEMA = "breachscope.external_holdout.v1"
FREEZE_SCHEMA = "breachscope.external_holdout.rules_freeze.v1"
RESULT_SCHEMA = "breachscope.external_holdout.result.v1"
VALID_LABELS = {"malicious", "benign", "ignore"}
VALID_EVALUATION_CLASSES = {"external_calibration", "external_baseline", "final_blind_holdout"}


class HoldoutError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _get(value: Any, key: str, default: Any = "") -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def event_identity_payload(event: Any) -> dict[str, str]:
    """Canonical identity used only for holdout accounting, not evidence integrity."""
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

    # Preserve historical keys for generic JSONL events that do not expose
    # Windows record identity, while disambiguating distinct EVTX records when
    # the source provides per-channel EventRecordID metadata.
    if channel:
        payload["channel"] = channel
    if event_record_id:
        payload["event_record_id"] = event_record_id

    return payload


def event_key(event: Any) -> str:
    payload = event_identity_payload(event)
    return hashlib.sha256(_json_dumps(payload).encode("utf-8")).hexdigest()


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def require_clean_repo(repo: Path) -> None:
    status = _git(repo, "status", "--porcelain", "-uall")
    if status:
        raise HoldoutError("repository working tree must be clean")


def rules_tree_hash(rules_dir: Path) -> tuple[str, int]:
    if not rules_dir.is_dir():
        raise HoldoutError(f"rules directory not found: {rules_dir}")

    files = sorted(
        p for p in rules_dir.rglob("*")
        if p.is_file() and p.suffix.casefold() in {".yml", ".yaml"}
    )
    if not files:
        raise HoldoutError(f"no YAML rule files found under: {rules_dir}")

    h = hashlib.sha256()
    for path in files:
        rel = path.relative_to(rules_dir).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(_sha256(path).encode("ascii"))
        h.update(b"\0")
    return h.hexdigest(), len(files)


def build_rules_freeze(repo: Path, rules_dir: Path) -> dict[str, Any]:
    require_clean_repo(repo)
    commit = _git(repo, "rev-parse", "HEAD")
    rule_hash, count = rules_tree_hash(rules_dir)
    return {
        "schema": FREEZE_SCHEMA,
        "repo_commit": commit,
        "rules_dir": str(rules_dir.resolve()),
        "rules_tree_sha256": rule_hash,
        "rule_file_count": count,
    }


def load_manifest(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise HoldoutError("holdout manifest must be a YAML mapping")
    if data.get("schema") != SCHEMA:
        raise HoldoutError(f"manifest schema must be {SCHEMA!r}")
    if data.get("kind") != "external_blind_holdout":
        raise HoldoutError("manifest kind must be external_blind_holdout")

    evaluation_class = str(data.get("evaluation_class") or "final_blind_holdout").strip()
    if evaluation_class not in VALID_EVALUATION_CLASSES:
        raise HoldoutError(
            f"evaluation_class must be one of {sorted(VALID_EVALUATION_CLASSES)}"
        )
    data["evaluation_class"] = evaluation_class

    protocol = data.get("protocol")
    if not isinstance(protocol, dict):
        raise HoldoutError("manifest protocol section is required")

    for key in (
        "independent_from_rule_authoring",
        "ground_truth_prepared_without_breachscope_findings",
        "final_holdout_seen_before_rule_freeze",
    ):
        if not isinstance(protocol.get(key), bool):
            raise HoldoutError(f"protocol.{key} must be an explicit boolean")

    if protocol.get("ground_truth_prepared_without_breachscope_findings") is not True:
        raise HoldoutError(
            "protocol.ground_truth_prepared_without_breachscope_findings must be true"
        )

    if evaluation_class == "final_blind_holdout":
        required_attestations = {
            "independent_from_rule_authoring": True,
            "final_holdout_seen_before_rule_freeze": False,
        }
        for key, expected in required_attestations.items():
            if protocol.get(key) is not expected:
                raise HoldoutError(
                    f"protocol.{key} must be explicitly {expected!r} for final_blind_holdout; "
                    "this is a recorded self-attestation, not independent proof"
                )

    files = data.get("files")
    if not isinstance(files, list) or not files:
        raise HoldoutError("manifest files must be a non-empty list")

    seen = set()
    for row in files:
        if not isinstance(row, dict):
            raise HoldoutError("each manifest file entry must be a mapping")
        rel = str(row.get("path") or "").strip()
        digest = str(row.get("sha256") or "").strip().lower()
        fmt = str(row.get("format") or "").strip().lower()
        if not rel or rel in seen:
            raise HoldoutError("manifest file paths must be non-empty and unique")
        seen.add(rel)
        if not re_full_sha256(digest):
            raise HoldoutError(f"invalid sha256 for manifest file: {rel}")
        if fmt not in {"jsonl", "evtx"}:
            raise HoldoutError(f"unsupported format {fmt!r} for {rel}")

    scenarios = data.get("scenarios") or []
    if not isinstance(scenarios, list):
        raise HoldoutError("manifest scenarios must be a list when provided")
    known_files = {str(row["path"]) for row in files}
    seen_scenarios: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise HoldoutError("each scenario entry must be a mapping")
        scenario_id = str(scenario.get("scenario_id") or "").strip()
        if not scenario_id or scenario_id in seen_scenarios:
            raise HoldoutError("scenario_id values must be non-empty and unique")
        seen_scenarios.add(scenario_id)
        source_files = scenario.get("source_files") or []
        expected = scenario.get("expected_techniques") or []
        if not isinstance(source_files, list) or not source_files:
            raise HoldoutError(f"scenario {scenario_id}: source_files must be a non-empty list")
        if len({str(x) for x in source_files}) != len(source_files):
            raise HoldoutError(f"scenario {scenario_id}: source_files must be unique")
        unknown = sorted({str(x) for x in source_files} - known_files)
        if unknown:
            raise HoldoutError(
                f"scenario {scenario_id}: unknown source_files: {unknown}"
            )
        if not isinstance(expected, list) or not expected:
            raise HoldoutError(
                f"scenario {scenario_id}: expected_techniques must be a non-empty list"
            )
        if len({str(x).upper() for x in expected}) != len(expected):
            raise HoldoutError(
                f"scenario {scenario_id}: expected_techniques must be unique"
            )

    return data


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def verify_corpus(manifest: dict[str, Any], corpus_root: Path) -> list[dict[str, Any]]:
    corpus_root = corpus_root.resolve()
    verified = []
    for row in manifest["files"]:
        rel = Path(str(row["path"]))
        if rel.is_absolute() or ".." in rel.parts:
            raise HoldoutError(f"unsafe manifest path: {rel}")
        path = (corpus_root / rel).resolve()
        try:
            path.relative_to(corpus_root)
        except ValueError as exc:
            raise HoldoutError(f"manifest path escapes corpus root: {rel}") from exc
        if not path.is_file():
            raise HoldoutError(f"corpus file not found: {rel}")
        actual = _sha256(path)
        expected = str(row["sha256"]).lower()
        if actual != expected:
            raise HoldoutError(
                f"corpus hash mismatch for {rel}: expected={expected} actual={actual}"
            )
        verified.append({**row, "_absolute_path": path})
    return verified


def _iter_jsonl_dicts(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for index, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HoldoutError(f"invalid JSONL {path}:{index}: {exc}") from exc
            if not isinstance(row, dict):
                raise HoldoutError(f"JSONL row must be an object: {path}:{index}")
            yield row


def _convert_one_evtx(path: Path) -> list[dict[str, Any]]:
    """Use BreachScope's current EVTX conversion path without redefining parsing."""
    from breachscope.ingest import convert_evtx_dir

    temp_root = Path(tempfile.mkdtemp(prefix="breachscope-holdout-evtx-"))
    try:
        input_dir = temp_root / "input"
        input_dir.mkdir()
        local = input_dir / path.name
        try:
            os.link(path, local)
        except OSError:
            shutil.copy2(path, local)

        converted = convert_evtx_dir(input_dir)
        if converted is None:
            raise HoldoutError(f"EVTX conversion returned no output for {path}")
        converted = Path(converted)
        jsonl_files = sorted(converted.rglob("*.jsonl"))
        if not jsonl_files:
            raise HoldoutError(f"EVTX conversion produced no JSONL for {path}")

        rows = []
        for jsonl in jsonl_files:
            rows.extend(_iter_jsonl_dicts(jsonl))
        return rows
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def load_corpus_records(
    manifest: dict[str, Any], corpus_root: Path
) -> list[dict[str, Any]]:
    verified = verify_corpus(manifest, corpus_root)
    records: list[dict[str, Any]] = []
    seen_keys: dict[str, tuple[str, int]] = {}

    for row in verified:
        path: Path = row["_absolute_path"]
        fmt = str(row["format"]).lower()
        source_name = str(row["path"])
        source_records = (
            list(_iter_jsonl_dicts(path))
            if fmt == "jsonl"
            else _convert_one_evtx(path)
        )
        for record_index, raw in enumerate(source_records, 1):
            key = event_key(raw)
            if key in seen_keys:
                prev = seen_keys[key]
                raise HoldoutError(
                    "duplicate event identity in holdout corpus: "
                    f"{source_name}:{record_index} duplicates {prev[0]}:{prev[1]}; "
                    "the identity contract must be disambiguated before scoring"
                )
            seen_keys[key] = (source_name, record_index)
            records.append(
                {
                    "event_key": key,
                    "source_file": source_name,
                    "record_index": record_index,
                    "identity": event_identity_payload(raw),
                    "raw": raw,
                }
            )

    if not records:
        raise HoldoutError("holdout corpus contains zero events")
    return records


def write_index(records: list[dict[str, Any]], path: Path) -> None:
    """Write analyst-labeling index. It contains no detector findings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in records:
            public = {
                "event_key": row["event_key"],
                "source_file": row["source_file"],
                "record_index": row["record_index"],
                "identity": row["identity"],
                "label": "",
                "allowed_labels": ["malicious", "benign", "ignore"],
                "expected_techniques": [],
                "notes": "",
            }
            f.write(json.dumps(public, ensure_ascii=False) + "\n")


def load_labels(path: Path, expected_sha256: str | None = None) -> dict[str, dict[str, Any]]:
    if expected_sha256:
        actual = _sha256(path)
        if actual != expected_sha256.lower():
            raise HoldoutError(
                f"labels hash mismatch: expected={expected_sha256} actual={actual}"
            )

    labels: dict[str, dict[str, Any]] = {}
    for row in _iter_jsonl_dicts(path):
        key = str(row.get("event_key") or "").strip()
        label = str(row.get("label") or "").strip().lower()
        if not re_full_sha256(key):
            raise HoldoutError("every label row needs a valid event_key")
        if label not in VALID_LABELS:
            raise HoldoutError(f"invalid label {label!r} for event {key}")
        if key in labels:
            raise HoldoutError(f"duplicate label for event {key}")
        techniques = row.get("expected_techniques") or []
        if not isinstance(techniques, list):
            raise HoldoutError("expected_techniques must be a list")
        labels[key] = {
            "label": label,
            "expected_techniques": [str(x).upper() for x in techniques],
            "notes": str(row.get("notes") or ""),
        }
    return labels


def require_complete_labels(
    records: list[dict[str, Any]], labels: dict[str, dict[str, Any]]
) -> None:
    record_keys = {row["event_key"] for row in records}
    label_keys = set(labels)
    missing = sorted(record_keys - label_keys)
    extra = sorted(label_keys - record_keys)
    if missing or extra:
        raise HoldoutError(
            f"label coverage must be exact: missing={len(missing)} extra={len(extra)}"
        )


def _record_to_event(raw: dict[str, Any]):
    from breachscope.schemas import Event

    identity = event_identity_payload(raw)
    params = inspect.signature(Event).parameters
    candidate = {
        "timestamp": identity["timestamp"],
        "host": identity["host"],
        "source": identity["source"],
        "event_id": identity["event_id"],
        "user": identity["user"],
        "command_line": identity["command_line"],
        "raw": raw,
    }
    kwargs = {k: v for k, v in candidate.items() if k in params}
    return Event(**kwargs)


def _verify_freeze(repo: Path, rules_dir: Path, freeze_path: Path) -> dict[str, Any]:
    require_clean_repo(repo)
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    if freeze.get("schema") != FREEZE_SCHEMA:
        raise HoldoutError("invalid rules freeze schema")
    current_commit = _git(repo, "rev-parse", "HEAD")
    current_hash, count = rules_tree_hash(rules_dir)
    if freeze.get("repo_commit") != current_commit:
        raise HoldoutError(
            f"repo commit changed since freeze: {freeze.get('repo_commit')} != {current_commit}"
        )
    if freeze.get("rules_tree_sha256") != current_hash:
        raise HoldoutError("rules tree changed since freeze")
    if int(freeze.get("rule_file_count", -1)) != count:
        raise HoldoutError("rule file count changed since freeze")
    return freeze


def confusion_from_flagged(
    records: list[dict[str, Any]],
    labels: dict[str, dict[str, Any]],
    flagged_keys: set[str],
) -> dict[str, int]:
    values = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for row in records:
        key = row["event_key"]
        label = labels[key]["label"]
        if label == "ignore":
            continue
        malicious = label == "malicious"
        flagged = key in flagged_keys
        if malicious and flagged:
            values["tp"] += 1
        elif malicious and not flagged:
            values["fn"] += 1
        elif not malicious and flagged:
            values["fp"] += 1
        else:
            values["tn"] += 1
    return values


def scenario_outcomes(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    techniques_by_key: Mapping[str, set[str]],
) -> dict[str, Any]:
    outcomes = []
    for scenario in manifest.get("scenarios") or []:
        scenario_id = str(scenario["scenario_id"])
        source_files = {str(x) for x in scenario["source_files"]}
        expected = {str(x).upper() for x in scenario["expected_techniques"]}
        keys = {
            row["event_key"]
            for row in records
            if row["source_file"] in source_files
        }
        observed: set[str] = set()
        for key in keys:
            observed.update(techniques_by_key.get(key, set()))
        matched = expected & observed
        missing = expected - observed
        outcomes.append(
            {
                "scenario_id": scenario_id,
                "source_files": sorted(source_files),
                "event_count": len(keys),
                "expected_techniques": sorted(expected),
                "observed_techniques": sorted(observed),
                "matched_techniques": sorted(matched),
                "missing_techniques": sorted(missing),
                "technique_recall": _safe_div(len(matched), len(expected)),
                "status": "hit" if not missing else "miss",
            }
        )
    hits = sum(row["status"] == "hit" for row in outcomes)
    misses = sum(row["status"] == "miss" for row in outcomes)
    return {
        "total": len(outcomes),
        "hits": hits,
        "misses": misses,
        "hit_rate": _safe_div(hits, len(outcomes)),
        "outcomes": outcomes,
    }


def _safe_div(a: int, b: int) -> float:
    return float(a) / float(b) if b else 0.0


def score_holdout(
    *,
    repo: Path,
    manifest_path: Path,
    corpus_root: Path,
    labels_path: Path,
    freeze_path: Path,
    rules_dir: Path,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    labels_cfg = manifest.get("labels") or {}
    if not isinstance(labels_cfg, dict):
        raise HoldoutError("manifest labels section must be a mapping")
    expected_labels_hash = str(labels_cfg.get("sha256") or "").strip().lower() or None
    if expected_labels_hash and not re_full_sha256(expected_labels_hash):
        raise HoldoutError("manifest labels.sha256 must be a SHA-256 hex digest")

    freeze = _verify_freeze(repo, rules_dir, freeze_path)
    records = load_corpus_records(manifest, corpus_root)
    labels = load_labels(labels_path, expected_labels_hash)
    require_complete_labels(records, labels)

    from breachscope.analyzer import apply_rules
    from breachscope.rules import load_rules

    rules = load_rules(rules_dir)
    events = [_record_to_event(row["raw"]) for row in records]
    key_by_object = {id(event): row["event_key"] for event, row in zip(events, records)}

    tracemalloc.start()
    start = time.perf_counter()
    findings = list(apply_rules(events, rules))
    runtime_seconds = time.perf_counter() - start
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    flagged_keys: set[str] = set()
    techniques_by_key: dict[str, set[str]] = defaultdict(set)
    unknown_finding_events = 0

    for finding in findings:
        event = getattr(finding, "event", None)
        key = key_by_object.get(id(event))
        if key is None and event is not None:
            candidate = event_key(event)
            if any(row["event_key"] == candidate for row in records):
                key = candidate
        if key is None:
            unknown_finding_events += 1
            continue
        flagged_keys.add(key)
        technique = str(getattr(finding, "mitre_technique", "") or "").upper()
        if technique:
            techniques_by_key[key].add(technique)

    if unknown_finding_events:
        raise HoldoutError(
            f"{unknown_finding_events} finding(s) could not be mapped back to holdout events"
        )

    confusion = confusion_from_flagged(records, labels, flagged_keys)
    precision = _safe_div(confusion["tp"], confusion["tp"] + confusion["fp"])
    recall = _safe_div(confusion["tp"], confusion["tp"] + confusion["fn"])
    fpr = _safe_div(confusion["fp"], confusion["fp"] + confusion["tn"])

    expected_technique_total = 0
    expected_technique_hits = 0
    per_source = defaultdict(
        lambda: Counter(events=0, malicious=0, benign=0, ignore=0, scored=0, flagged=0)
    )

    for row in records:
        key = row["event_key"]
        label = labels[key]
        bucket = per_source[row["source_file"]]
        bucket["events"] += 1
        bucket[label["label"]] += 1
        if label["label"] != "ignore":
            bucket["scored"] += 1
        if key in flagged_keys:
            bucket["flagged"] += 1

        if label["label"] != "ignore":
            expected = set(label["expected_techniques"])
            if expected:
                expected_technique_total += len(expected)
                expected_technique_hits += len(expected & techniques_by_key.get(key, set()))

    ignored_keys = {
        row["event_key"] for row in records if labels[row["event_key"]]["label"] == "ignore"
    }
    scenario_metrics = scenario_outcomes(manifest, records, techniques_by_key)

    return {
        "schema": RESULT_SCHEMA,
        "kind": "external_holdout_measurement",
        "claim_boundary": {
            "production_detection_quality_certified": False,
            "independent_provenance_proven_by_tool": False,
            "ground_truth_quality_proven_by_tool": False,
            "evaluation_class": manifest["evaluation_class"],
            "manifest_declares_final_blind": manifest["evaluation_class"] == "final_blind_holdout",
            "note": (
                "Hashes and protocol self-attestations were enforced. "
                "External provenance, label quality, and representativeness require independent evidence."
            ),
        },
        "freeze": freeze,
        "corpus": {
            "manifest_sha256": _sha256(manifest_path),
            "labels_sha256": _sha256(labels_path),
            "events": len(records),
            "scored_events": sum(labels[r["event_key"]]["label"] != "ignore" for r in records),
            "ignored_events": sum(labels[r["event_key"]]["label"] == "ignore" for r in records),
            "malicious": sum(labels[r["event_key"]]["label"] == "malicious" for r in records),
            "benign": sum(labels[r["event_key"]]["label"] == "benign" for r in records),
            "source_files": len(manifest["files"]),
        },
        "detection": {
            "rules": len(rules),
            "findings": len(findings),
            "flagged_events": len(flagged_keys),
            "flagged_ignored_events": len(flagged_keys & ignored_keys),
            "confusion": confusion,
            "precision": precision,
            "recall": recall,
            "false_positive_rate": fpr,
            "expected_technique_hits": expected_technique_hits,
            "expected_technique_total": expected_technique_total,
            "expected_technique_recall": _safe_div(
                expected_technique_hits, expected_technique_total
            ),
        },
        "scenarios": scenario_metrics,
        "performance": {
            "runtime_seconds": runtime_seconds,
            "peak_memory_mb": peak_bytes / (1024 * 1024),
        },
        "per_source": {name: dict(counts) for name, counts in sorted(per_source.items())},
    }


def cmd_freeze(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    rules_dir = Path(args.rules_dir).resolve()
    payload = build_rules_freeze(repo, rules_dir)
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(payload, indent=2))
    print("Rules freeze written:", out)
    return 0


def cmd_index(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    records = load_corpus_records(manifest, Path(args.corpus_root))
    out = Path(args.out).resolve()
    write_index(records, out)
    print("Holdout event index written:", out)
    print("Events:", len(records))
    print("Detection rules executed: NO")
    print("Findings emitted: NO")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    result = score_holdout(
        repo=Path(args.repo).resolve(),
        manifest_path=Path(args.manifest).resolve(),
        corpus_root=Path(args.corpus_root).resolve(),
        labels_path=Path(args.labels).resolve(),
        freeze_path=Path(args.freeze).resolve(),
        rules_dir=Path(args.rules_dir).resolve(),
    )
    output_text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output_text, encoding="utf-8", newline="\n")
        print("Result written:", out)
    print(output_text)

    precision = result["detection"]["precision"]
    recall = result["detection"]["recall"]
    failed = False
    if args.min_precision is not None and precision < args.min_precision:
        print(
            f"FAIL: precision {precision:.4f} < requested {args.min_precision:.4f}",
            file=sys.stderr,
        )
        failed = True
    if args.min_recall is not None and recall < args.min_recall:
        print(
            f"FAIL: recall {recall:.4f} < requested {args.min_recall:.4f}",
            file=sys.stderr,
        )
        failed = True
    scenario_hit_rate = result["scenarios"]["hit_rate"]
    if (
        args.min_scenario_hit_rate is not None
        and scenario_hit_rate < args.min_scenario_hit_rate
    ):
        print(
            "FAIL: scenario hit rate "
            f"{scenario_hit_rate:.4f} < requested {args.min_scenario_hit_rate:.4f}",
            file=sys.stderr,
        )
        failed = True
    return 3 if failed else 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="BreachScope external/blind holdout evaluation protocol."
    )
    sub = ap.add_subparsers(dest="command", required=True)

    freeze = sub.add_parser("freeze", help="Freeze exact repository/rule state.")
    freeze.add_argument("--repo", default=".")
    freeze.add_argument("--rules-dir", default="rules")
    freeze.add_argument("--out", required=True)
    freeze.set_defaults(func=cmd_freeze)

    index = sub.add_parser(
        "index",
        help="Ingest/hash external corpus and emit a labeling index WITHOUT detection.",
    )
    index.add_argument("--manifest", required=True)
    index.add_argument("--corpus-root", required=True)
    index.add_argument("--out", required=True)
    index.set_defaults(func=cmd_index)

    score = sub.add_parser("score", help="Verify freeze/labels, run detection, measure.")
    score.add_argument("--repo", default=".")
    score.add_argument("--manifest", required=True)
    score.add_argument("--corpus-root", required=True)
    score.add_argument("--labels", required=True)
    score.add_argument("--freeze", required=True)
    score.add_argument("--rules-dir", default="rules")
    score.add_argument("--out")
    score.add_argument("--min-precision", type=float)
    score.add_argument("--min-recall", type=float)
    score.add_argument("--min-scenario-hit-rate", type=float)
    score.set_defaults(func=cmd_score)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except HoldoutError as exc:
        print(f"HOLDOUT ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
