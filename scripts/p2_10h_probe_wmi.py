#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from scripts.evaluate_external_holdout import _convert_one_evtx, event_identity_payload


def main() -> int:
    path = Path("out/p2_10h_wmi_probe/corpus/evtx-lm-wmi.evtx")
    rows = _convert_one_evtx(path)
    print(f"TOTAL_ROWS={len(rows)}")
    counts: dict[str, int] = {}
    for row in rows:
        eid = str(event_identity_payload(row).get("event_id") or "")
        counts[eid] = counts.get(eid, 0) + 1
    print("EVENT_COUNTS=" + json.dumps(counts, sort_keys=True))

    for idx, row in enumerate(rows):
        payload = event_identity_payload(row)
        eid = str(payload.get("event_id") or "")
        if eid not in {"4624", "4688"}:
            continue
        print(f"--- EVENT index={idx} event_id={eid} ---")
        print(json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
