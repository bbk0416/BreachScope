from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml


SCHEMA = "breachscope.p2_35e_socbed_timeline_one_pass.v1"
ANALYSIS_ID = "p2-35e-socbed-acsac2021-timeline-one-pass-v1"
ATTACKS = [
    "misc_sqlmap",
    "infect_email_exe",
    "c2_take_screenshot",
    "c2_exfiltration",
    "c2_mimikatz",
    "misc_download_malware",
    "misc_set_autostart",
    "misc_execute_malware",
]
RUN_ATTACK_RE = re.compile(r'\bevent=(?:"run_attack"|run_attack)(?=\s|\])')
ATTACK_RE = re.compile(r'\battack=(?:"([A-Za-z0-9_.-]+)"|([A-Za-z0-9_.-]+))(?=\s|\])')


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(tmp, path)


def acquire_global_lock(lock_path: Path) -> None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(
            f"analysis id already permanently locked: {lock_path}"
        ) from exc
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


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _user_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, Mapping):
        return str(value)
    name = _first(value.get("name"), value.get("username"))
    domain = value.get("domain")
    if name not in (None, ""):
        return f"{domain}\\{name}" if domain not in (None, "") else str(name)
    ident = _first(value.get("id"), value.get("identifier"))
    return "" if ident in (None, "") else str(ident)


def adapt_winlogbeat_row(raw: Mapping[str, Any]):
    """Map one source Winlogbeat/ECS row into the frozen BreachScope Event model."""
    from breachscope.canonical import enrich_event_dict
    from breachscope.schemas import Event

    if not isinstance(raw, Mapping):
        raise RuntimeError("Winlogbeat JSONL row must be an object")

    winlog = _mapping(raw.get("winlog"))
    event_data = _mapping(winlog.get("event_data"))
    event_obj = _mapping(raw.get("event"))
    host_obj = _mapping(raw.get("host"))
    agent_obj = _mapping(raw.get("agent"))
    process_obj = _mapping(raw.get("process"))
    user_obj = _mapping(_first(winlog.get("user"), raw.get("user")))

    timestamp = _first(raw.get("@timestamp"), raw.get("timestamp"))
    if timestamp in (None, ""):
        raise RuntimeError("Winlogbeat row has no timestamp")

    host = _first(
        winlog.get("computer_name"),
        host_obj.get("name"),
        host_obj.get("hostname"),
        agent_obj.get("hostname"),
        raw.get("computer_name"),
    )
    source = _first(
        winlog.get("provider_name"),
        event_obj.get("provider"),
        winlog.get("channel"),
        raw.get("source_name"),
    )
    event_id = _first(
        winlog.get("event_id"),
        event_obj.get("code"),
        raw.get("event_id"),
    )
    command_line = _first(
        event_data.get("CommandLine"),
        event_data.get("ProcessCommandLine"),
        process_obj.get("command_line"),
        raw.get("command_line"),
    )
    user = _user_text(user_obj)
    if not user:
        user = str(
            _first(
                event_data.get("User"),
                event_data.get("SubjectUserName"),
                event_data.get("TargetUserName"),
                event_data.get("AccountName"),
                event_data.get("UserName"),
                "",
            )
        )

    event_raw = dict(raw)
    for key, value in event_data.items():
        event_raw.setdefault(str(key), value)
    event_raw.setdefault("event_data", dict(event_data))

    channel = _first(winlog.get("channel"), raw.get("channel"))
    record_id = _first(
        winlog.get("record_id"),
        winlog.get("record_number"),
        raw.get("event_record_id"),
        raw.get("record_number"),
    )
    if channel not in (None, ""):
        event_raw.setdefault("channel", str(channel))
    if record_id not in (None, ""):
        event_raw.setdefault("event_record_id", str(record_id))

    candidate = {
        "timestamp": str(timestamp),
        "host": str(host or "unknown"),
        "source": str(source or "unknown"),
        "event_id": None if event_id in (None, "") else str(event_id),
        "level": str(_first(raw.get("log.level"), event_obj.get("severity"), "") or ""),
        "user": user,
        "command_line": None if command_line in (None, "") else str(command_line),
        "raw": event_raw,
    }
    candidate = enrich_event_dict(candidate)
    return Event(**candidate)


def _parse_timestamp(value: Any) -> datetime:
    from breachscope.utils import parse_timestamp

    parsed = parse_timestamp(str(value or ""))
    if parsed is None:
        raise RuntimeError(f"unparseable timestamp: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_attackconsole_timeline(text: str, expected_attacks: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not RUN_ATTACK_RE.search(line):
            continue
        attack_match = ATTACK_RE.search(line)
        if attack_match is None:
            raise RuntimeError(f"run_attack line has no attack field at line {line_no}")
        timestamp_token = line.split(None, 1)[0]
        parsed = _parse_timestamp(timestamp_token)
        rows.append(
            {
                "ordinal": len(rows) + 1,
                "attack": attack_match.group(1) or attack_match.group(2),
                "timestamp": parsed.isoformat(),
                "_dt": parsed,
                "line_number": line_no,
            }
        )

    names = [row["attack"] for row in rows]
    if names != expected_attacks:
        raise RuntimeError(
            f"attackconsole run_attack order mismatch: {names!r} != {expected_attacks!r}"
        )
    for left, right in zip(rows, rows[1:]):
        if right["_dt"] <= left["_dt"]:
            raise RuntimeError("attackconsole run_attack timestamps are not strictly increasing")
    return rows


def build_step_windows(
    timeline: list[dict[str, Any]],
    maximum_window_seconds: int,
) -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []
    for index, row in enumerate(timeline):
        start = row["_dt"]
        hard_end = start + timedelta(seconds=maximum_window_seconds)
        if index + 1 < len(timeline):
            end = min(hard_end, timeline[index + 1]["_dt"])
        else:
            end = hard_end
        if end <= start:
            raise RuntimeError("non-positive source attack window")
        windows.append(
            {
                "ordinal": row["ordinal"],
                "attack": row["attack"],
                "start": start,
                "end": end,
                "start_timestamp": start.isoformat(),
                "end_timestamp": end.isoformat(),
                "window_seconds": (end - start).total_seconds(),
            }
        )
    return windows


def timestamp_window_index(ts: datetime, windows: list[dict[str, Any]]) -> int | None:
    for index, row in enumerate(windows):
        if row["start"] <= ts < row["end"]:
            return index
    return None


def rules_tree_hash(rules_dir: Path) -> tuple[str, int]:
    files = sorted(
        p for p in rules_dir.rglob("*")
        if p.is_file() and p.suffix.casefold() in {".yml", ".yaml"}
    )
    if not files:
        raise RuntimeError("no YAML rule files found")
    h = hashlib.sha256()
    for path in files:
        rel = path.relative_to(rules_dir).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        canonical = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        h.update(hashlib.sha256(canonical).hexdigest().encode("ascii"))
        h.update(b"\0")
    return h.hexdigest(), len(files)


def verify_product(repo: Path, contract: dict[str, Any]) -> dict[str, Any]:
    frozen = contract["frozen_product"]
    baseline = frozen["repo_commit"]
    diff = subprocess.run(
        ["git", "diff", "--quiet", baseline, "--", "breachscope", "rules"],
        cwd=repo,
        check=False,
    )
    if diff.returncode != 0:
        raise RuntimeError("breachscope/ or rules/ changed after frozen product commit")
    rules_hash, rule_file_count = rules_tree_hash(repo / "rules")
    if rules_hash != frozen["rules_tree_sha256"]:
        raise RuntimeError("rules tree SHA mismatch")
    if rule_file_count != frozen["rule_file_count"]:
        raise RuntimeError("rule file count mismatch")
    return {
        "baseline_repo_commit": baseline,
        "breachscope_and_rules_match_frozen_commit": True,
        "rules_tree_sha256": rules_hash,
        "rule_file_count": rule_file_count,
    }


def _counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(v for v in values if v).items()))


def _scenario_start(scenario: Any) -> datetime | None:
    starts: list[datetime] = []
    for chain in getattr(scenario, "chains", []) or []:
        value = getattr(chain, "start_time", None)
        if value not in (None, ""):
            try:
                starts.append(_parse_timestamp(value))
            except RuntimeError:
                pass
    return min(starts) if starts else None


def summarize_alignment(
    events: list[Any],
    findings: list[Any],
    chains: list[Any],
    scenarios: list[Any],
    windows: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = [
        {
            "ordinal": window["ordinal"],
            "attack": window["attack"],
            "start_timestamp": window["start_timestamp"],
            "end_timestamp": window["end_timestamp"],
            "window_seconds": window["window_seconds"],
            "event_count": 0,
            "finding_count": 0,
            "chain_start_count": 0,
            "scenario_start_count": 0,
            "finding_rule_ids": [],
            "finding_techniques": [],
            "finding_hosts": [],
            "chain_types": [],
            "scenario_stages": [],
            "first_finding_delay_seconds": None,
            "first_chain_delay_seconds": None,
            "first_scenario_delay_seconds": None,
        }
        for window in windows
    ]

    def add_delay(row: dict[str, Any], key: str, ts: datetime, start: datetime) -> None:
        delay = (ts - start).total_seconds()
        current = row[key]
        if current is None or delay < current:
            row[key] = delay

    for event in events:
        ts = _parse_timestamp(getattr(event, "timestamp", ""))
        idx = timestamp_window_index(ts, windows)
        if idx is not None:
            rows[idx]["event_count"] += 1

    for finding in findings:
        ts = _parse_timestamp(getattr(finding.event, "timestamp", ""))
        idx = timestamp_window_index(ts, windows)
        if idx is None:
            continue
        row = rows[idx]
        row["finding_count"] += 1
        row["finding_rule_ids"].append(str(getattr(finding, "rule_id", "") or ""))
        techniques = getattr(finding, "mitre_techniques", None) or []
        if not techniques and getattr(finding, "mitre_technique", None):
            techniques = [getattr(finding, "mitre_technique")]
        row["finding_techniques"].extend(str(x) for x in techniques)
        row["finding_hosts"].append(str(getattr(finding.event, "host", "") or ""))
        add_delay(row, "first_finding_delay_seconds", ts, windows[idx]["start"])

    for chain in chains:
        start = getattr(chain, "start_time", None)
        if start is None:
            continue
        ts = start if isinstance(start, datetime) else _parse_timestamp(start)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ts = ts.astimezone(timezone.utc)
        idx = timestamp_window_index(ts, windows)
        if idx is None:
            continue
        row = rows[idx]
        row["chain_start_count"] += 1
        row["chain_types"].append(str(getattr(chain, "chain_type", "") or ""))
        add_delay(row, "first_chain_delay_seconds", ts, windows[idx]["start"])

    for scenario in scenarios:
        ts = _scenario_start(scenario)
        if ts is None:
            continue
        idx = timestamp_window_index(ts, windows)
        if idx is None:
            continue
        row = rows[idx]
        row["scenario_start_count"] += 1
        row["scenario_stages"].append(str(getattr(scenario, "attack_stage", "") or ""))
        add_delay(row, "first_scenario_delay_seconds", ts, windows[idx]["start"])

    for row in rows:
        row["finding_rule_ids"] = sorted(set(row["finding_rule_ids"]))
        row["finding_techniques"] = sorted(set(row["finding_techniques"]))
        row["finding_hosts"] = sorted(set(row["finding_hosts"]))
        row["chain_types"] = sorted(set(row["chain_types"]))
        row["scenario_stages"] = sorted(set(row["scenario_stages"]))
        row["has_events"] = row["event_count"] > 0
        row["has_findings"] = row["finding_count"] > 0
        row["has_chain_start"] = row["chain_start_count"] > 0
        row["has_scenario_start"] = row["scenario_start_count"] > 0

    count = len(rows)
    return {
        "step_count": count,
        "steps": rows,
        "steps_with_events": sum(row["has_events"] for row in rows),
        "steps_with_findings": sum(row["has_findings"] for row in rows),
        "steps_with_chain_starts": sum(row["has_chain_start"] for row in rows),
        "steps_with_scenario_starts": sum(row["has_scenario_start"] for row in rows),
        "finding_window_occupancy_fraction": (
            sum(row["has_findings"] for row in rows) / count if count else 0.0
        ),
        "chain_start_window_occupancy_fraction": (
            sum(row["has_chain_start"] for row in rows) / count if count else 0.0
        ),
        "scenario_start_window_occupancy_fraction": (
            sum(row["has_scenario_start"] for row in rows) / count if count else 0.0
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run preregistered P2-35E SOCBED timeline alignment measurement."
    )
    parser.add_argument("--contract", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if sys.version_info[:2] != (3, 11):
        raise SystemExit("P2-35E requires Python 3.11")
    if sys.platform != "win32":
        raise SystemExit("P2-35E requires Windows")

    repo = REPO_ROOT
    script = Path(__file__).resolve()
    contract_path = Path(args.contract).resolve()
    archive_path = Path(args.archive).resolve()
    out_dir = Path(args.out_dir).resolve()

    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    if contract["analysis_id"] != ANALYSIS_ID:
        raise RuntimeError("analysis id mismatch")
    runner_sha = sha256_file(script)
    if runner_sha != contract["runner"]["sha256"]:
        raise RuntimeError("runner SHA mismatch")

    product = verify_product(repo, contract)
    source = contract["source"]
    archive_cfg = source["dataset_archive"]
    if archive_path.stat().st_size != archive_cfg["size_bytes"]:
        raise RuntimeError("dataset archive size mismatch")
    archive_sha = sha256_file(archive_path)
    if archive_sha != archive_cfg["sha256"]:
        raise RuntimeError("dataset archive SHA256 mismatch")

    if out_dir.exists():
        raise RuntimeError("output directory already exists before canonical lock acquisition")

    global_lock_rel = Path(str(contract["runner"]["global_lock_file"]))
    if global_lock_rel.is_absolute() or ".." in global_lock_rel.parts:
        raise RuntimeError("global lock path must be repository-relative")
    global_lock_path = (repo / global_lock_rel).resolve()
    try:
        global_lock_path.relative_to(repo.resolve())
    except ValueError as exc:
        raise RuntimeError("global lock path escapes repository root") from exc

    acquire_global_lock(global_lock_path)
    out_dir.mkdir(parents=True, exist_ok=False)

    result_path = out_dir / contract["runner"]["result_file"]
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "analysis_id": ANALYSIS_ID,
        "status": "started",
        "contract_sha256": sha256_file(contract_path),
        "runner_sha256": runner_sha,
        "product": product,
        "source": {
            "archive_size_bytes": archive_path.stat().st_size,
            "archive_sha256": archive_sha,
        },
    }
    write_json(result_path, result)

    try:
        selected_cfg = source["selected_windows_member"]
        timing_cfg = source["timing_anchor_member"]
        with zipfile.ZipFile(archive_path, "r") as zf:
            selected_info = zf.getinfo(selected_cfg["path"])
            timing_info = zf.getinfo(timing_cfg["path"])
            if selected_info.file_size != selected_cfg["size_bytes"]:
                raise RuntimeError("selected Windows member size mismatch")
            if timing_info.file_size != timing_cfg["size_bytes"]:
                raise RuntimeError("timing anchor member size mismatch")
            timing_bytes = zf.read(timing_info)
            selected_bytes = zf.read(selected_info)

        selected_sha = sha256_bytes(selected_bytes)
        if selected_sha != selected_cfg["sha256"]:
            raise RuntimeError("selected Windows member SHA256 mismatch")
        timing_sha = sha256_bytes(timing_bytes)

        timeline = parse_attackconsole_timeline(
            timing_bytes.decode("utf-8", errors="strict"),
            list(contract["timeline"]["expected_attack_order"]),
        )
        windows = build_step_windows(
            timeline,
            int(contract["timeline"]["maximum_step_window_seconds"]),
        )

        raw_rows: list[dict[str, Any]] = []
        for line_no, line in enumerate(
            selected_bytes.decode("utf-8", errors="strict").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"invalid selected JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, dict):
                raise RuntimeError(f"selected JSONL row {line_no} is not an object")
            raw_rows.append(row)
        if not raw_rows:
            raise RuntimeError("selected Windows member contains zero JSONL rows")

        adapted = [adapt_winlogbeat_row(row) for row in raw_rows]
        from breachscope.normalizer import normalize
        from breachscope.rules import load_rules
        from breachscope.analyzer import apply_rules
        from breachscope.correlator import correlate_events
        from breachscope.scenario import infer_scenarios

        events = list(normalize(iter(adapted)))
        for event in events:
            _parse_timestamp(event.timestamp)

        started = time.perf_counter()
        rules = load_rules(repo / "rules")
        findings = list(apply_rules(events, rules))
        after_detection = time.perf_counter()
        chains = correlate_events(events, findings)
        after_correlation = time.perf_counter()
        scenarios = infer_scenarios(chains, findings)
        after_scenario = time.perf_counter()

        alignment = summarize_alignment(events, findings, chains, scenarios, windows)

        result.update(
            {
                "status": "completed",
                "source": {
                    **result["source"],
                    "selected_windows_member": {
                        "path": selected_cfg["path"],
                        "size_bytes": selected_info.file_size,
                        "sha256": selected_sha,
                    },
                    "timing_anchor_member": {
                        "path": timing_cfg["path"],
                        "size_bytes": timing_info.file_size,
                        "sha256": timing_sha,
                    },
                },
                "timeline": {
                    "source": "attackconsole event=run_attack records",
                    "attacks": [
                        {
                            "ordinal": row["ordinal"],
                            "attack": row["attack"],
                            "timestamp": row["timestamp"],
                            "line_number": row["line_number"],
                        }
                        for row in timeline
                    ],
                },
                "measurement": {
                    "raw_jsonl_rows": len(raw_rows),
                    "events": len(events),
                    "unknown_host_events": sum(
                        str(event.host or "").casefold() == "unknown" for event in events
                    ),
                    "unknown_source_events": sum(
                        str(event.source or "").casefold() == "unknown" for event in events
                    ),
                    "missing_event_id_events": sum(
                        getattr(event, "event_id", None) in (None, "") for event in events
                    ),
                    "findings": len(findings),
                    "finding_rule_counts": _counter_dict(
                        [str(getattr(f, "rule_id", "") or "") for f in findings]
                    ),
                    "finding_technique_counts": _counter_dict(
                        [
                            str(tech)
                            for f in findings
                            for tech in (
                                getattr(f, "mitre_techniques", None)
                                or ([getattr(f, "mitre_technique")] if getattr(f, "mitre_technique", None) else [])
                            )
                        ]
                    ),
                    "chains": len(chains),
                    "chain_type_counts": _counter_dict(
                        [str(getattr(c, "chain_type", "") or "") for c in chains]
                    ),
                    "scenarios": len(scenarios),
                    "scenario_stage_counts": _counter_dict(
                        [str(getattr(s, "attack_stage", "") or "") for s in scenarios]
                    ),
                    "timeline_alignment": alignment,
                    "timing_seconds": {
                        "detection": after_detection - started,
                        "correlation": after_correlation - after_detection,
                        "scenario": after_scenario - after_correlation,
                    },
                },
                "claim_boundary": {
                    "source_attack_invocation_order": "MEASURED_FROM_SOURCE_TIMING_LOG",
                    "temporal_window_occupancy": "MEASURED",
                    "attack_step_semantic_attribution": "NOT_EVALUATED",
                    "event_level_precision": "NOT_EVALUATED",
                    "event_level_recall": "NOT_EVALUATED",
                    "chain_precision": "NOT_EVALUATED",
                    "chain_recall": "NOT_EVALUATED",
                    "scenario_precision": "NOT_EVALUATED",
                    "scenario_recall": "NOT_EVALUATED",
                    "production_reconstruction_quality": "NOT_CLAIMED",
                },
            }
        )
        write_json(result_path, result)
        return 0
    except Exception as exc:
        result["status"] = "failed"
        result["exception"] = f"{type(exc).__name__}: {exc}"
        write_json(result_path, result)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
