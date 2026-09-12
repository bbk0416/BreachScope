from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

EXPECTED_ARCHIVE_SHA256 = "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
EXPECTED_DETECTOR_COMMIT = "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
EXPECTED_RULE_TREE = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
EXPECTED_RULE_COUNT = 66
EXPECTED_RULE_FILE_COUNT = 4
EXPECTED_EVTX_FILES = 381
EXPECTED_TOTAL_RECORDS = 1741090
EXPECTED_BINDING_PARSE_ERRORS = 51
SCHEMA = "breachscope.p2_13c_win11_benign_full_rulepack.v1"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def text(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_xml_event(xml_text: str, Event, event_key: str):
    root = ET.fromstring(xml_text)
    provider_node = root.find("e:System/e:Provider", NS)
    event_id_node = root.find("e:System/e:EventID", NS)
    time_node = root.find("e:System/e:TimeCreated", NS)
    computer_node = root.find("e:System/e:Computer", NS)
    level_node = root.find("e:System/e:Level", NS)
    channel_node = root.find("e:System/e:Channel", NS)
    record_node = root.find("e:System/e:EventRecordID", NS)

    provider = provider_node.attrib.get("Name", "") if provider_node is not None else ""
    event_id = text(event_id_node.text if event_id_node is not None else None)
    timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    host = text(computer_node.text if computer_node is not None else None) or ""
    level = text(level_node.text if level_node is not None else None)
    channel = text(channel_node.text if channel_node is not None else None) or ""
    record_id = text(record_node.text if record_node is not None else None) or ""

    raw: dict[str, Any] = {}
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        unnamed = 0
        for node in list(event_data):
            if local_name(node.tag) != "Data":
                continue
            name = node.attrib.get("Name") or f"Data{unnamed}"
            if "Name" not in node.attrib:
                unnamed += 1
            value = node.text or ""
            if name in raw:
                existing = raw[name]
                raw[name] = existing + [value] if isinstance(existing, list) else [existing, value]
            else:
                raw[name] = value

    user_data = root.find("e:UserData", NS)
    if user_data is not None:
        for node in user_data.iter():
            if node is user_data or list(node):
                continue
            name = local_name(node.tag)
            if name and name not in raw:
                raw[name] = node.text or ""

    raw["System"] = {
        "Provider": provider,
        "EventID": event_id or "",
        "Channel": channel,
        "EventRecordID": record_id,
        "Computer": host,
    }
    raw["_p2_13_event_key"] = event_key

    command_line = text(raw.get("CommandLine")) or text(raw.get("ProcessCommandLine"))
    user = (
        text(raw.get("User"))
        or text(raw.get("TargetUserName"))
        or text(raw.get("SubjectUserName"))
        or text(raw.get("AccountName"))
        or text(raw.get("UserName"))
    )
    return Event(
        timestamp=timestamp,
        host=host,
        source=provider or channel,
        event_id=event_id,
        level=level,
        user=user,
        command_line=command_line,
        raw=raw,
    )


def is_security_file(path: Path) -> bool:
    return path.name.casefold() == "security.evtx"


def inventory_units(root: Path) -> tuple[list[Path], list[dict[str, Any]]]:
    files = sorted(p for p in root.rglob("*.evtx") if p.is_file())
    if len(files) != EXPECTED_EVTX_FILES:
        raise SystemExit(f"EVTX file count drift: {len(files)} != {EXPECTED_EVTX_FILES}")
    units: list[dict[str, Any]] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        if is_security_file(path):
            units.append({"kind": "file", "path": path, "id": f"file:{rel}"})
            continue
        with Evtx(str(path)) as evtx:
            for local_index, _ in enumerate(evtx.chunks()):
                units.append({"kind": "chunk", "path": path, "chunk": local_index, "id": f"chunk:{rel}#{local_index}"})
    return files, units


def iter_file_events(path: Path, root: Path, Event, counters: Counter) -> Iterator[Any]:
    rel = path.relative_to(root).as_posix()
    with Evtx(str(path)) as evtx:
        for record in evtx.records():
            counters["total_records"] += 1
            try:
                xml_text = record.xml()
                event = parse_xml_event(xml_text, Event, f"{rel}#record:{record.record_num()}")
            except Exception:
                counters["parse_errors"] += 1
                continue
            yield event


def iter_chunk_events(path: Path, chunk_index: int, root: Path, Event, counters: Counter) -> Iterator[Any]:
    rel = path.relative_to(root).as_posix()
    with Evtx(str(path)) as evtx:
        selected = None
        for i, chunk in enumerate(evtx.chunks()):
            if i == chunk_index:
                selected = chunk
                break
        if selected is None:
            raise SystemExit(f"missing chunk {chunk_index} in {rel}")
        for record in selected.records():
            counters["total_records"] += 1
            try:
                xml_text = record.xml()
                event = parse_xml_event(xml_text, Event, f"{rel}#record:{record.record_num()}")
            except Exception:
                counters["parse_errors"] += 1
                continue
            yield event


def verify_detector(detector: Path, freeze: dict[str, Any]) -> None:
    head = subprocess.check_output(["git", "-C", str(detector), "rev-parse", "HEAD"], text=True).strip()
    if head != EXPECTED_DETECTOR_COMMIT:
        raise SystemExit(f"detector commit drift: {head}")
    if freeze.get("repo_commit") != EXPECTED_DETECTOR_COMMIT:
        raise SystemExit("freeze detector commit mismatch")
    if freeze.get("rules_tree_sha256") != EXPECTED_RULE_TREE:
        raise SystemExit(f"freeze rule tree mismatch: {freeze.get('rules_tree_sha256')}")
    if int(freeze.get("rule_file_count", -1)) != EXPECTED_RULE_FILE_COUNT:
        raise SystemExit("freeze rule file count mismatch")


def run_shard(args: argparse.Namespace) -> int:
    archive = Path(args.archive)
    root = Path(args.extracted)
    detector = Path(args.detector).resolve()
    freeze = json.loads(Path(args.freeze).read_text(encoding="utf-8"))
    if sha256_file(archive) != EXPECTED_ARCHIVE_SHA256:
        raise SystemExit("archive SHA mismatch")
    verify_detector(detector, freeze)

    sys.path.insert(0, str(detector))
    from breachscope.analyzer import apply_rules
    from breachscope.rules import load_rules
    from breachscope.schemas import Event

    rules = list(load_rules(detector / "rules"))
    if len(rules) != EXPECTED_RULE_COUNT:
        raise SystemExit(f"rule count drift: {len(rules)}")

    files, units = inventory_units(root)
    selected = [u for i, u in enumerate(units) if i % args.shards == args.shard]
    counters: Counter = Counter()
    findings_by_rule: Counter = Counter()
    flagged_by_rule: dict[str, set[str]] = defaultdict(set)
    flagged_events: set[str] = set()
    severity_counts: Counter = Counter()
    samples: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for unit in selected:
        stream = (
            iter_file_events(unit["path"], root, Event, counters)
            if unit["kind"] == "file"
            else iter_chunk_events(unit["path"], int(unit["chunk"]), root, Event, counters)
        )
        for finding in apply_rules(stream, rules):
            counters["findings"] += 1
            findings_by_rule[finding.rule_id] += 1
            severity_counts[str(finding.severity)] += 1
            event_key = str(finding.event.raw.get("_p2_13_event_key") or "")
            if event_key:
                flagged_events.add(event_key)
                flagged_by_rule[finding.rule_id].add(event_key)
            if len(samples[finding.rule_id]) < args.samples_per_rule:
                samples[finding.rule_id].append({
                    "event_key": event_key,
                    "timestamp": finding.event.timestamp,
                    "host": finding.event.host,
                    "source": finding.event.source,
                    "event_id": finding.event.event_id,
                    "user": finding.event.user,
                    "command_line": finding.event.command_line,
                    "matched_value": finding.matched_value,
                    "severity": finding.severity,
                    "mitre_techniques": list(finding.mitre_techniques),
                })

    result = {
        "schema": SCHEMA,
        "mode": "shard",
        "evaluation_class": "fresh_benign_by_source_intent_operational_alert_volume",
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "detector_repo_commit": EXPECTED_DETECTOR_COMMIT,
        "rules_tree_sha256": EXPECTED_RULE_TREE,
        "rules": len(rules),
        "rule_file_count": EXPECTED_RULE_FILE_COUNT,
        "shard": args.shard,
        "shards": args.shards,
        "evtx_files": len(files),
        "total_units": len(units),
        "selected_units": len(selected),
        "unit_ids": [u["id"] for u in selected],
        "total_records": counters["total_records"],
        "parse_errors": counters["parse_errors"],
        "findings": counters["findings"],
        "flagged_events": len(flagged_events),
        "findings_by_rule": dict(sorted(findings_by_rule.items())),
        "flagged_events_by_rule": {k: len(v) for k, v in sorted(flagged_by_rule.items())},
        "severity_counts": dict(sorted(severity_counts.items())),
        "samples_by_rule": dict(sorted(samples.items())),
        "tuning_performed": False,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("shard", "selected_units", "total_records", "parse_errors", "findings", "flagged_events")}, sort_keys=True))
    return 0


def merge_counter(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: Counter = Counter()
    for row in rows:
        out.update({str(k): int(v) for k, v in row.get(key, {}).items()})
    return dict(sorted(out.items()))


def run_aggregate(args: argparse.Namespace) -> int:
    paths = sorted(Path(args.inputs).glob("shard-*.json"))
    if len(paths) != args.shards:
        raise SystemExit(f"expected {args.shards} shard results, got {len(paths)}")
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    rows.sort(key=lambda r: r["shard"])
    if [r["shard"] for r in rows] != list(range(args.shards)):
        raise SystemExit("shard identity mismatch")
    for row in rows:
        assert row["schema"] == SCHEMA
        assert row["archive_sha256"] == EXPECTED_ARCHIVE_SHA256
        assert row["detector_repo_commit"] == EXPECTED_DETECTOR_COMMIT
        assert row["rules_tree_sha256"] == EXPECTED_RULE_TREE
        assert row["rules"] == EXPECTED_RULE_COUNT
        assert row["rule_file_count"] == EXPECTED_RULE_FILE_COUNT
        assert row["shards"] == args.shards
        assert row["tuning_performed"] is False

    totals = {r["total_units"] for r in rows}
    if len(totals) != 1:
        raise SystemExit(f"total-unit disagreement: {totals}")
    total_units = next(iter(totals))
    unit_ids = [u for r in rows for u in r["unit_ids"]]
    if len(unit_ids) != len(set(unit_ids)):
        raise SystemExit("duplicate scored units")
    if len(unit_ids) != total_units:
        raise SystemExit(f"unit coverage mismatch: {len(unit_ids)} != {total_units}")
    total_records = sum(int(r["total_records"]) for r in rows)
    parse_errors = sum(int(r["parse_errors"]) for r in rows)
    if total_records != EXPECTED_TOTAL_RECORDS:
        raise SystemExit(f"record coverage mismatch: {total_records} != {EXPECTED_TOTAL_RECORDS}")
    if parse_errors != EXPECTED_BINDING_PARSE_ERRORS:
        raise SystemExit(f"parse-error drift: {parse_errors} != {EXPECTED_BINDING_PARSE_ERRORS}")

    findings = sum(int(r["findings"]) for r in rows)
    flagged_events = sum(int(r["flagged_events"]) for r in rows)
    findings_by_rule = merge_counter(rows, "findings_by_rule")
    flagged_by_rule = merge_counter(rows, "flagged_events_by_rule")
    severity_counts = merge_counter(rows, "severity_counts")
    samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        for rule_id, rule_samples in row.get("samples_by_rule", {}).items():
            for sample in rule_samples:
                if len(samples[rule_id]) < args.samples_per_rule:
                    samples[rule_id].append(sample)

    parsed_records = total_records - parse_errors
    result = {
        "schema": SCHEMA,
        "mode": "aggregate",
        "evaluation_class": "fresh_benign_by_source_intent_operational_alert_volume",
        "selection_record": "external_baseline/p2_13a_win11_benign_selection.yaml",
        "binding_record": "external_baseline/p2_13b_win11_benign_binding.yaml",
        "source_repository": "NextronSystems/evtx-baseline",
        "release": "v0.8.4",
        "asset": "win11-client-2023.tgz",
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "detector_repo_commit": EXPECTED_DETECTOR_COMMIT,
        "rules_tree_sha256": EXPECTED_RULE_TREE,
        "rules": EXPECTED_RULE_COUNT,
        "rule_file_count": EXPECTED_RULE_FILE_COUNT,
        "evtx_files": EXPECTED_EVTX_FILES,
        "scored_units": total_units,
        "total_records": total_records,
        "parse_errors": parse_errors,
        "parsed_records": parsed_records,
        "findings": findings,
        "flagged_events": flagged_events,
        "detected_rule_count": len(findings_by_rule),
        "findings_by_rule": findings_by_rule,
        "flagged_events_by_rule": flagged_by_rule,
        "severity_counts": severity_counts,
        "samples_by_rule": dict(sorted(samples.items())),
        "flagged_event_fraction_of_parsed_records": (flagged_events / parsed_records) if parsed_records else None,
        "tuning_performed_after_result": False,
        "claim_boundary": {
            "fresh_public_benign_by_source_intent_corpus": True,
            "event_level_benign_ground_truth": "NOT_AVAILABLE",
            "representative_production_population": "NOT_CLAIMED",
            "operational_alert_volume": "MEASURED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "note": "This is a one-pass full frozen-rulepack operational alert-volume measurement on a precommitted public benign-by-source-intent corpus. The flagged-event fraction is descriptive alert volume, not a production false-positive rate. The 51 parse errors are excluded from parsed-record denominators and retained explicitly.",
        },
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("shard")
    sp.add_argument("--archive", required=True)
    sp.add_argument("--extracted", required=True)
    sp.add_argument("--detector", required=True)
    sp.add_argument("--freeze", required=True)
    sp.add_argument("--shard", type=int, required=True)
    sp.add_argument("--shards", type=int, required=True)
    sp.add_argument("--samples-per-rule", type=int, default=3)
    sp.add_argument("--output", required=True)
    ag = sub.add_parser("aggregate")
    ag.add_argument("--inputs", required=True)
    ag.add_argument("--shards", type=int, required=True)
    ag.add_argument("--samples-per-rule", type=int, default=5)
    ag.add_argument("--output", required=True)
    args = ap.parse_args()
    return run_shard(args) if args.cmd == "shard" else run_aggregate(args)


if __name__ == "__main__":
    raise SystemExit(main())
