from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import yaml

EXPECTED_DETECTOR_COMMIT = "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
EXPECTED_RULE_TREE = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
EXPECTED_ARCHIVE_SHA256 = "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5"
EXPECTED_ARCHIVE_BYTES = 13944973
EXPECTED_EVENTS = 196081
EXPECTED_RULES = 66


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _events(archive: Path, Event, counters: dict[str, Any]) -> Iterator[Any]:
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        if names != ["apt29_evals_day1_manual_2020-05-01225525.json"]:
            raise AssertionError(names)
        with zf.open(names[0]) as fh:
            for line_no, raw_line in enumerate(fh, 1):
                try:
                    raw = json.loads(raw_line)
                except Exception:
                    counters["parse_errors"] += 1
                    continue
                counters["events"] += 1
                raw["_p2_12_line"] = line_no
                source = _text(raw.get("SourceName")) or _text(raw.get("Channel")) or ""
                event_id = _text(raw.get("EventID"))
                command_line = _text(raw.get("CommandLine")) or _text(raw.get("ProcessCommandLine"))
                user = (
                    _text(raw.get("User"))
                    or _text(raw.get("AccountName"))
                    or _text(raw.get("TargetUserName"))
                    or _text(raw.get("SubjectUserName"))
                )
                yield Event(
                    timestamp=(
                        _text(raw.get("UtcTime"))
                        or _text(raw.get("EventTime"))
                        or _text(raw.get("@timestamp"))
                        or ""
                    ),
                    host=_text(raw.get("Hostname")) or _text(raw.get("host")) or "",
                    source=source,
                    event_id=event_id,
                    level=_text(raw.get("Severity")) or _text(raw.get("SeverityValue")),
                    user=user,
                    command_line=command_line,
                    raw=raw,
                )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--detector", required=True, type=Path)
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--binding", required=True, type=Path)
    p.add_argument("--freeze", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()

    detector = args.detector.resolve()
    archive = args.archive.resolve()
    binding = yaml.safe_load(args.binding.read_text(encoding="utf-8"))
    freeze = json.loads(args.freeze.read_text(encoding="utf-8"))

    detector_commit = subprocess.check_output(
        ["git", "-C", str(detector), "rev-parse", "HEAD"], text=True
    ).strip()
    assert detector_commit == EXPECTED_DETECTOR_COMMIT
    assert freeze["repo_commit"] == EXPECTED_DETECTOR_COMMIT
    assert freeze["rules_tree_sha256"] == EXPECTED_RULE_TREE
    assert int(freeze["rule_file_count"]) == 4
    assert archive.stat().st_size == EXPECTED_ARCHIVE_BYTES
    assert _sha256(archive) == EXPECTED_ARCHIVE_SHA256
    assert binding["archive_binding"]["sha256"] == EXPECTED_ARCHIVE_SHA256
    assert binding["protocol_state"]["labels_bound_before_detection"] is True
    assert binding["protocol_state"]["detector_executed_on_selected_archive"] is False

    sys.path.insert(0, str(detector))
    from breachscope.analyzer import apply_rules
    from breachscope.rules import load_rules
    from breachscope.schemas import Event

    rules = list(load_rules(detector / "rules"))
    assert len(rules) == EXPECTED_RULES

    counters = {"events": 0, "parse_errors": 0}
    findings = 0
    flagged_lines: set[int] = set()
    rule_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()

    for finding in apply_rules(_events(archive, Event, counters), rules):
        findings += 1
        rule_counts[finding.rule_id] += 1
        line = finding.event.raw.get("_p2_12_line")
        if isinstance(line, int):
            flagged_lines.add(line)
        for technique in finding.mitre_techniques:
            technique_counts[str(technique).upper()] += 1

    assert counters["events"] == EXPECTED_EVENTS
    assert counters["parse_errors"] == 0

    source_labels = {str(x).upper() for x in binding["label_binding"]["technique_ids"]}
    observed = set(technique_counts)
    overlap = sorted(source_labels & observed)
    missing = sorted(source_labels - observed)

    result = {
        "schema": "breachscope.p2_12c_fresh_external_result.v1",
        "evaluation_class": "fresh_external_holdout",
        "selection_id": "p2-12a-otrf-apt29-day1-v1",
        "binding_id": "p2-12b-otrf-apt29-day1-v1",
        "source_repository": "OTRF/Security-Datasets",
        "source_commit": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
        "detector_repo_commit": detector_commit,
        "rules_tree_sha256": freeze["rules_tree_sha256"],
        "rules": len(rules),
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "events": counters["events"],
        "parse_errors": counters["parse_errors"],
        "findings": findings,
        "flagged_events": len(flagged_lines),
        "detected_rule_count": len(rule_counts),
        "detected_rule_counts": dict(sorted(rule_counts.items())),
        "detected_technique_count": len(observed),
        "detected_technique_counts": dict(sorted(technique_counts.items())),
        "source_legacy_technique_total": len(source_labels),
        "exact_legacy_id_overlap_count": len(overlap),
        "exact_legacy_id_overlap": overlap,
        "exact_legacy_id_not_observed": missing,
        "exact_legacy_id_overlap_fraction": len(overlap) / len(source_labels),
        "claim_boundary": {
            "fresh_external_corpus": True,
            "event_level_labels": "NOT_AVAILABLE",
            "production_detection_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "note": "The exact legacy ATT&CK-ID overlap is a corpus-level source-label overlap measure, not event-level recall or a production detection rate. No post-result legacy-to-modern ATT&CK remapping is applied.",
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
