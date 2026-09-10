#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from Evtx.Evtx import Evtx

from breachscope.ingest import _extract_from_xml

EXPECTED_EVTX_FILES = 352
EXPECTED_NON_SYSMON_FILES = 351
EXPECTED_NON_SYSMON_EVENTS = 34423


def _raw_fields(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("raw")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    event_data = raw.get("event_data")
    if isinstance(event_data, dict):
        out.update(event_data)
    for key, value in raw.items():
        if key in {"event_data", "system", "canonical"}:
            continue
        if key not in out:
            out[key] = value
    return out


def _pick(fields: dict[str, Any], names: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in names:
        value = fields.get(name)
        if value not in (None, "", []):
            result[name] = value
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    evtx_files = sorted(root.rglob("*.evtx"))
    sysmon_files = [p for p in evtx_files if "sysmon" in p.name.casefold()]
    non_sysmon_files = [p for p in evtx_files if p not in sysmon_files]

    if len(evtx_files) != EXPECTED_EVTX_FILES:
        raise SystemExit(f"expected {EXPECTED_EVTX_FILES} EVTX files, got {len(evtx_files)}")
    if len(non_sysmon_files) != EXPECTED_NON_SYSMON_FILES:
        raise SystemExit(
            f"expected {EXPECTED_NON_SYSMON_FILES} non-Sysmon EVTX files, got {len(non_sysmon_files)}; "
            f"Sysmon candidates={[str(p.relative_to(root)) for p in sysmon_files]}"
        )

    total_events = 0
    parse_errors = 0
    event_4720 = 0
    security_source_4720 = 0
    matches: list[dict[str, Any]] = []
    per_file_counts: list[dict[str, Any]] = []

    interesting = [
        "TargetUserName", "TargetDomainName", "TargetSid",
        "SubjectUserName", "SubjectDomainName", "SubjectUserSid",
        "SamAccountName", "DisplayName", "UserPrincipalName",
        "HomeDirectory", "ScriptPath", "UserAccountControl",
    ]

    for path in non_sysmon_files:
        file_events = 0
        file_errors = 0
        file_4720 = 0
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    event = _extract_from_xml(record.xml())
                except Exception:
                    parse_errors += 1
                    file_errors += 1
                    continue
                if not isinstance(event, dict):
                    parse_errors += 1
                    file_errors += 1
                    continue
                total_events += 1
                file_events += 1
                if str(event.get("event_id") or "") != "4720":
                    continue
                event_4720 += 1
                file_4720 += 1
                source = str(event.get("source") or "")
                if source.casefold() == "microsoft-windows-security-auditing":
                    security_source_4720 += 1
                fields = _raw_fields(event)
                matches.append({
                    "file": str(path.relative_to(root)).replace("\\", "/"),
                    "timestamp": str(event.get("timestamp") or ""),
                    "host": str(event.get("host") or ""),
                    "source": source,
                    "event_id": str(event.get("event_id") or ""),
                    "user": str(event.get("user") or ""),
                    "fields": _pick(fields, interesting),
                })
        if file_events or file_errors:
            per_file_counts.append({
                "file": str(path.relative_to(root)).replace("\\", "/"),
                "events": file_events,
                "parse_errors": file_errors,
                "event_4720": file_4720,
            })

    if total_events != EXPECTED_NON_SYSMON_EVENTS:
        raise SystemExit(
            f"expected {EXPECTED_NON_SYSMON_EVENTS} non-Sysmon events, got {total_events}"
        )
    if parse_errors != 0:
        raise SystemExit(f"expected 0 parse errors, got {parse_errors}")

    result = {
        "schema": "breachscope.p2_11d_security_4720_benign_scan.v1",
        "corpus": {
            "repository": "NextronSystems/evtx-baseline",
            "release_tag": "v0.8.4",
            "asset_name": "win10-client.tgz",
            "asset_sha256_expected": "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e",
            "label_policy": "benign_by_source_intent",
        },
        "coverage": {
            "evtx_files": len(evtx_files),
            "sysmon_files_excluded_from_this_scan": len(sysmon_files),
            "sysmon_file_names": [str(p.relative_to(root)).replace("\\", "/") for p in sysmon_files],
            "non_sysmon_evtx_files": len(non_sysmon_files),
            "non_sysmon_events": total_events,
            "parse_errors": parse_errors,
        },
        "predicate": {
            "event_id": 4720,
            "source_exact": "Microsoft-Windows-Security-Auditing",
        },
        "counts": {
            "event_id_4720_any_source": event_4720,
            "exact_security_4720_matches": security_source_4720,
        },
        "matches": matches,
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "current_rulepack_false_positive_rate": "NOT_CLAIMED",
            "note": "Counts only the exact Security 4720 predicate in this pinned public benign-by-source-intent corpus."
        },
        "files_with_records": per_file_counts,
    }
    out_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps({
        "evtx_files": len(evtx_files),
        "non_sysmon_files": len(non_sysmon_files),
        "non_sysmon_events": total_events,
        "event_4720": event_4720,
        "exact_security_4720": security_source_4720,
        "parse_errors": parse_errors,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
