#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from Evtx.Evtx import Evtx
from breachscope.ingest import _extract_from_xml

SCENARIOS = ["T1136.001-4", "T1136.001-5"]
FIELDS = [
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
    "TargetUserName", "TargetDomainName", "TargetSid", "SamAccountName",
    "UserAccountControl", "PrivilegeList",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--atomic-root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.atomic_root).resolve()
    matches = []
    parsed = 0
    errors = 0
    for scenario in SCENARIOS:
        path = root / "ttp_evtx" / scenario / f"{scenario}_Security.evtx"
        if not path.is_file():
            raise SystemExit(f"missing {path}")
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
                parsed += 1
                if str(event.get("event_id") or "") != "4720":
                    continue
                raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
                ed = raw.get("event_data") if isinstance(raw.get("event_data"), dict) else {}
                matches.append({
                    "scenario_id": scenario,
                    "timestamp": str(event.get("timestamp") or ""),
                    "host": str(event.get("host") or ""),
                    "source": str(event.get("source") or ""),
                    "fields": {k: ed.get(k) for k in FIELDS if ed.get(k) not in (None, "", [])},
                })

    result = {"parsed_security_events": parsed, "parse_errors": errors, "event_4720": matches}
    Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, ensure_ascii=False))
    if errors:
        raise SystemExit(f"parse errors: {errors}")
    if len(matches) != 2:
        raise SystemExit(f"expected 2 Event 4720 records, got {len(matches)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
