from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from breachscope.analyzer import apply_rules
from breachscope.brawl import event_from_brawl_record, extract_bsf_steps
from breachscope.brawl_score import finding_techniques, hosts_equivalent, technique_matches
from breachscope.rules import load_rules
from scripts.brawl_attack_holdout_one_pass import _data_members, _iter_json_records


ANALYSIS_ID = "brawl-posthoc-miss-diagnosis-v1"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _sanitize_text(value: Any) -> str:
    text = str(value or "")
    text = re.sub(
        r'(?i)(/password\s*:\s*")[^"]*(")',
        r'\1<redacted>\2',
        text,
    )
    text = re.sub(
        r'(?i)(\bnet"?\s+use\s+\S+\s+)\S+(\s+/user:)',
        r'\1<redacted>\2',
        text,
    )
    return text


def _bsf_event_summary(event: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "host",
        "object",
        "action",
        "time",
        "happened_after",
        "happened_before",
        "command_line",
        "exe",
        "image_path",
        "file_path",
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
    )
    result: dict[str, Any] = {}
    for key in keys:
        if key not in event:
            continue
        value = event.get(key)
        if key == "command_line":
            value = _sanitize_text(value)
        result[key] = value
    return result


def _rule_techniques(rule: Any) -> list[str]:
    values = list(getattr(rule, "mitre_techniques", ()) or ())
    single = getattr(rule, "mitre_technique", None)
    if not values and single not in (None, ""):
        values = [str(single)]
    return [str(value).strip().upper() for value in values if str(value).strip()]


def _window_match(host: str, timestamp: datetime | None, windows: Iterable[dict[str, Any]]) -> bool:
    if timestamp is None:
        return False
    for window in windows:
        lower = _parse_time(window.get("window_start"))
        upper = _parse_time(window.get("window_end"))
        if lower is None or upper is None:
            continue
        if hosts_equivalent(host, window.get("host")) and lower <= timestamp <= upper:
            return True
    return False


def _time_match(timestamp: datetime | None, windows: Iterable[dict[str, Any]]) -> bool:
    if timestamp is None:
        return False
    for window in windows:
        lower = _parse_time(window.get("window_start"))
        upper = _parse_time(window.get("window_end"))
        if lower is not None and upper is not None and lower <= timestamp <= upper:
            return True
    return False


def _host_match(host: str, windows: Iterable[dict[str, Any]]) -> bool:
    return any(hosts_equivalent(host, window.get("host")) for window in windows)


def _distance_seconds(timestamp: datetime | None, windows: Iterable[dict[str, Any]], host: str) -> float | None:
    if timestamp is None:
        return None
    distances: list[float] = []
    for window in windows:
        if not hosts_equivalent(host, window.get("host")):
            continue
        lower = _parse_time(window.get("window_start"))
        upper = _parse_time(window.get("window_end"))
        if lower is None or upper is None:
            continue
        if lower <= timestamp <= upper:
            return 0.0
        if timestamp < lower:
            distances.append((lower - timestamp).total_seconds())
        else:
            distances.append((timestamp - upper).total_seconds())
    return min(distances) if distances else None


def run(repo: Path, archive: Path, sealed_result_path: Path) -> dict[str, Any]:
    sealed = json.loads(sealed_result_path.read_text(encoding="utf-8"))
    expected_archive_sha = sealed["source"]["archive_sha256"]
    actual_archive_sha = _sha256(archive)
    if actual_archive_sha != expected_archive_sha:
        raise RuntimeError("archive SHA-256 does not match sealed canonical result")

    events = []
    bsf_steps: list[dict[str, Any]] = []
    with zipfile.ZipFile(archive) as zf:
        for info in _data_members(zf):
            for record in _iter_json_records(zf.read(info), info.filename):
                record_type = str(record.get("type") or "").strip()
                if record_type in {"sysmon", "win_event"}:
                    event = event_from_brawl_record(record)
                    if event is not None:
                        events.append(event)
                elif record_type == "bsf_events":
                    bsf_steps.extend(extract_bsf_steps(record))

    bsf_steps_by_id = {
        str(step.get("step_id") or ""): step
        for step in bsf_steps
        if step.get("step_id")
    }

    rules = load_rules(repo / "rules")
    findings = list(apply_rules(events, rules))

    findings_by_rule = collections.Counter(f.rule_id for f in findings)
    findings_by_technique: collections.Counter[str] = collections.Counter()
    findings_by_host = collections.Counter(f.event.host for f in findings)
    for finding in findings:
        for technique in finding_techniques(finding):
            findings_by_technique[technique] += 1

    expected_ids = sorted({
        str(row.get("expected_current_technique") or "").upper()
        for row in sealed["score"]["pair_rows"]
        if row.get("expected_current_technique")
    })
    rule_coverage: dict[str, list[str]] = {}
    for expected in expected_ids:
        matched = []
        for rule in rules:
            if any(technique_matches(expected, observed) for observed in _rule_techniques(rule)):
                matched.append(rule.id)
        rule_coverage[expected] = sorted(set(matched))

    event_times = [(event, _parse_time(event.timestamp)) for event in events]
    finding_times = [(finding, _parse_time(finding.event.timestamp)) for finding in findings]

    rows = []
    classifications = collections.Counter()
    for pair in sealed["score"]["pair_rows"]:
        expected = str(pair.get("expected_current_technique") or "").upper()
        windows = list(pair.get("referenced_event_windows") or [])

        expected_findings = [
            (finding, ts)
            for finding, ts in finding_times
            if any(technique_matches(expected, observed) for observed in finding_techniques(finding))
        ]
        expected_same_host = [
            (finding, ts) for finding, ts in expected_findings
            if _host_match(finding.event.host, windows)
        ]
        expected_in_time_any_host = [
            (finding, ts) for finding, ts in expected_findings
            if _time_match(ts, windows)
        ]
        any_finding_same_host_time = [
            (finding, ts) for finding, ts in finding_times
            if _window_match(finding.event.host, ts, windows)
        ]
        expected_same_host_time = [
            (finding, ts) for finding, ts in expected_findings
            if _window_match(finding.event.host, ts, windows)
        ]

        telemetry_in_window = [
            event for event, ts in event_times
            if _window_match(event.host, ts, windows)
        ]
        telemetry_sources = collections.Counter(event.source for event in telemetry_in_window)
        telemetry_event_ids = collections.Counter(str(event.event_id) for event in telemetry_in_window)
        command_samples: list[str] = []
        for event in telemetry_in_window:
            cmd = str(event.command_line or "").strip()
            if cmd and cmd not in command_samples:
                command_samples.append(_sanitize_text(cmd))
            if len(command_samples) >= 5:
                break

        nearest_same_host_expected = None
        for finding, ts in expected_same_host:
            distance = _distance_seconds(ts, windows, finding.event.host)
            if distance is not None:
                nearest_same_host_expected = (
                    distance if nearest_same_host_expected is None
                    else min(nearest_same_host_expected, distance)
                )

        coverage = rule_coverage.get(expected, [])
        if not coverage:
            classification = "NO_CURRENT_RULE_COVERAGE"
        elif not telemetry_in_window:
            classification = "NO_NORMALIZED_TELEMETRY_IN_BSF_WINDOW"
        elif expected_same_host_time:
            classification = "WOULD_HAVE_MATCHED_CANONICAL_UNEXPECTED"
        elif any_finding_same_host_time:
            classification = "FINDING_IN_WINDOW_WRONG_TECHNIQUE"
        elif expected_same_host:
            classification = "EXPECTED_TECHNIQUE_SAME_HOST_OUTSIDE_WINDOW"
        elif expected_in_time_any_host:
            classification = "EXPECTED_TECHNIQUE_IN_TIME_OTHER_HOST"
        elif expected_findings:
            classification = "EXPECTED_TECHNIQUE_FINDING_ELSEWHERE"
        else:
            classification = "TELEMETRY_PRESENT_NO_EXPECTED_TECHNIQUE_FINDING"
        classifications[classification] += 1

        bsf_step = bsf_steps_by_id.get(str(pair.get("step_id") or ""), {})
        bsf_reference_events = [
            _bsf_event_summary(dict(event))
            for event in list(bsf_step.get("events") or [])
            if isinstance(event, dict)
        ]

        rows.append({
            "step_id": pair.get("step_id"),
            "bsf_reference_events": bsf_reference_events,
            "upstream_technique": pair.get("upstream_technique"),
            "expected_current_technique": expected,
            "canonical_status": pair.get("status"),
            "classification": classification,
            "current_rule_ids": coverage,
            "expected_technique_findings_anywhere": len(expected_findings),
            "expected_technique_findings_same_host": len(expected_same_host),
            "expected_technique_findings_in_time_any_host": len(expected_in_time_any_host),
            "findings_same_host_time_any_technique": len(any_finding_same_host_time),
            "expected_technique_findings_same_host_time": len(expected_same_host_time),
            "nearest_same_host_expected_technique_distance_seconds": nearest_same_host_expected,
            "normalized_events_same_host_time": len(telemetry_in_window),
            "telemetry_sources": dict(telemetry_sources.most_common()),
            "telemetry_event_ids": dict(telemetry_event_ids.most_common()),
            "command_line_samples": command_samples,
        })

    return {
        "schema": "breachscope.brawl_posthoc_miss_diagnosis.v1",
        "analysis_id": ANALYSIS_ID,
        "status": "POSTHOC_COMPLETED",
        "canonical_analysis_id": sealed["analysis_id"],
        "canonical_result_status": sealed["status"],
        "canonical_pair_hits": sealed["score"]["counts"]["pair_hits"],
        "canonical_pair_misses": sealed["score"]["counts"]["pair_misses"],
        "canonical_pair_errors": sealed["score"]["counts"]["pair_errors"],
        "source_archive_sha256": actual_archive_sha,
        "host_event_count": len(events),
        "finding_count": len(findings),
        "bsf_step_count": len(bsf_steps),
        "findings_by_rule": dict(findings_by_rule.most_common()),
        "findings_by_technique": dict(findings_by_technique.most_common()),
        "findings_by_host": dict(findings_by_host.most_common()),
        "rule_coverage": rule_coverage,
        "pair_classifications": dict(classifications.most_common()),
        "rows": rows,
        "claim_boundaries": {
            "canonical_result_modified": False,
            "canonical_rerun": False,
            "posthoc_only": True,
            "event_level_recall": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument(
        "--sealed-result",
        default="external_baseline/results/brawl_de4d7da/result.json",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    result = run(
        repo,
        Path(args.archive).resolve(),
        (repo / args.sealed_result).resolve(),
    )
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "analysis_id": result["analysis_id"],
        "status": result["status"],
        "finding_count": result["finding_count"],
        "findings_by_rule": result["findings_by_rule"],
        "findings_by_technique": result["findings_by_technique"],
        "pair_classifications": result["pair_classifications"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())