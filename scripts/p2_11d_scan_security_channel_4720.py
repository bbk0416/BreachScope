#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from Evtx.Evtx import Evtx
from breachscope.ingest import _extract_from_xml


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    candidates = sorted(p for p in root.rglob("*.evtx") if "security" in p.name.casefold())
    if not candidates:
        raise SystemExit("no EVTX filename containing 'security' found")

    total = 0
    errors = 0
    matches = []
    for path in candidates:
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    event = _extract_from_xml(record.xml())
                except Exception:
                    errors += 1
                    continue
                if not isinstance(event, dict):
                    errors += 1
                    continue
                total += 1
                if str(event.get("event_id") or "") != "4720":
                    continue
                raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
                event_data = raw.get("event_data") if isinstance(raw.get("event_data"), dict) else {}
                matches.append({
                    "file": str(path.relative_to(root)).replace("\\", "/"),
                    "timestamp": str(event.get("timestamp") or ""),
                    "source": str(event.get("source") or ""),
                    "host": str(event.get("host") or ""),
                    "TargetUserName": event_data.get("TargetUserName"),
                    "TargetDomainName": event_data.get("TargetDomainName"),
                    "TargetSid": event_data.get("TargetSid"),
                    "SubjectUserName": event_data.get("SubjectUserName"),
                    "SubjectDomainName": event_data.get("SubjectDomainName"),
                })

    result = {
        "candidate_security_filenames": [str(p.relative_to(root)).replace("\\", "/") for p in candidates],
        "events_in_candidate_files": total,
        "parse_errors": errors,
        "event_4720_count": len(matches),
        "matches": matches,
    }
    Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"files": len(candidates), "events": total, "event_4720": len(matches), "errors": errors}))
    if errors:
        raise SystemExit(f"parse errors: {errors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
