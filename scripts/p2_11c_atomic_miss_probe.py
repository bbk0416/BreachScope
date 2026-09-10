#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from Evtx.Evtx import Evtx

from breachscope.ingest import _extract_from_xml

SCENARIOS = [
    ("T1003-1", "T1003"),
    ("T1003-2", "T1003"),
    ("T1006-1", "T1006"),
    ("T1027-2", "T1027"),
    ("T1007-1", "T1007"),
    ("T1007-2", "T1007"),
    ("T1021.001-1", "T1021.001"),
    ("T1021.001-2", "T1021.001"),
    ("T1047-1", "T1047"),
    ("T1047-2", "T1047"),
    ("T1136.001-4", "T1136.001"),
    ("T1136.001-5", "T1136.001"),
]

INTERESTING_FIELDS = [
    "Image", "ParentImage", "CommandLine", "ParentCommandLine",
    "NewProcessName", "ProcessName", "ProcessId", "NewProcessId",
    "TargetObject", "Details", "EventType", "RuleName",
    "ScriptBlockText", "Payload", "ContextInfo", "HostApplication",
    "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName",
    "LogonType", "IpAddress", "IpPort", "TargetUserName", "TargetDomainName",
    "SubjectUserName", "SubjectDomainName", "MemberName", "MemberSid",
    "ObjectName", "ObjectType", "AccessMask", "OperationType",
    "DestinationIp", "DestinationHostname", "DestinationPort",
    "SourceIp", "SourcePort", "Protocol", "QueryName",
]


def _flatten_raw(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key in {"event_data", "system", "canonical"}:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[str(key)] = value
    event_data = raw.get("event_data")
    if isinstance(event_data, dict):
        for key, value in event_data.items():
            if key not in out:
                out[str(key)] = value
    return out


def _short(value: Any, limit: int = 1200) -> Any:
    if isinstance(value, list):
        return [_short(v, limit=limit) for v in value[:8]]
    text = str(value)
    if len(text) > limit:
        return text[:limit] + "...[truncated]"
    return value


def _provider(event: dict[str, Any]) -> str:
    return str(event.get("source") or "")


def _event_id(event: dict[str, Any]) -> str:
    return str(event.get("event_id") or "")


def _record(event: dict[str, Any], file_name: str) -> dict[str, Any]:
    raw = _flatten_raw(event.get("raw"))
    fields: dict[str, Any] = {}
    for key in INTERESTING_FIELDS:
        value = raw.get(key)
        if value not in (None, "", []):
            fields[key] = _short(value)

    cmd = event.get("command_line")
    if cmd not in (None, "") and "CommandLine" not in fields:
        fields["normalized_command_line"] = _short(cmd)

    return {
        "file": file_name,
        "timestamp": str(event.get("timestamp") or ""),
        "host": str(event.get("host") or ""),
        "source": _provider(event),
        "event_id": _event_id(event),
        "user": str(event.get("user") or ""),
        "fields": fields,
    }


def _is_interesting(rec: dict[str, Any]) -> bool:
    source = rec["source"].casefold()
    event_id = rec["event_id"]
    if rec["fields"]:
        return True
    if event_id in {
        "1", "3", "10", "11", "12", "13", "14",
        "4624", "4688", "4697", "4720", "4722", "4728", "4732",
        "7045", "4103", "4104", "1149", "21", "22", "24", "25",
    }:
        return True
    if "powershell" in source or "terminalservices" in source or "sysmon" in source:
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--atomic-root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    atomic_root = Path(args.atomic_root).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "schema": "breachscope.p2_11c_atomic_miss_probe.v1",
        "source_commit_expected": "8de5fa8f158b4d72d1e3c6f07053162c90ee6238",
        "scenario_count": len(SCENARIOS),
        "scenarios": [],
    }

    details_path = out_dir / "interesting-events.jsonl"
    total_events = 0
    total_interesting = 0

    with details_path.open("w", encoding="utf-8", newline="\n") as details:
        for scenario_id, expected in SCENARIOS:
            scenario_dir = atomic_root / "ttp_evtx" / scenario_id
            evtx_files = sorted(scenario_dir.glob("*.evtx"))
            if len(evtx_files) != 5:
                raise SystemExit(f"{scenario_id}: expected 5 EVTX files, got {len(evtx_files)}")

            provider_event = Counter()
            provider_count = Counter()
            field_presence = Counter()
            scenario_events = 0
            scenario_interesting = 0
            parse_errors = 0

            for fp in evtx_files:
                with Evtx(str(fp)) as log:
                    for record in log.records():
                        try:
                            event = _extract_from_xml(record.xml())
                        except Exception:
                            parse_errors += 1
                            continue
                        if not isinstance(event, dict):
                            parse_errors += 1
                            continue
                        scenario_events += 1
                        total_events += 1
                        src = _provider(event)
                        eid = _event_id(event)
                        provider_count[src] += 1
                        provider_event[f"{src}|{eid}"] += 1
                        rec = _record(event, fp.name)
                        for key in rec["fields"]:
                            field_presence[key] += 1
                        if _is_interesting(rec):
                            scenario_interesting += 1
                            total_interesting += 1
                            details.write(json.dumps({
                                "scenario_id": scenario_id,
                                "expected_technique": expected,
                                **rec,
                            }, ensure_ascii=False, sort_keys=True) + "\n")

            summary["scenarios"].append({
                "scenario_id": scenario_id,
                "expected_technique": expected,
                "evtx_files": [fp.name for fp in evtx_files],
                "events": scenario_events,
                "interesting_events": scenario_interesting,
                "parse_errors": parse_errors,
                "providers": dict(provider_count.most_common()),
                "provider_event_ids": dict(provider_event.most_common()),
                "field_presence": dict(field_presence.most_common()),
            })

    summary["total_events"] = total_events
    summary["total_interesting_events"] = total_interesting
    summary["total_parse_errors"] = sum(x["parse_errors"] for x in summary["scenarios"])
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps({
        "scenario_count": len(SCENARIOS),
        "total_events": total_events,
        "interesting_events": total_interesting,
        "parse_errors": summary["total_parse_errors"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
