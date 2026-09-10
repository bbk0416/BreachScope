#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from Evtx.Evtx import Evtx

from p2_11f_t1006_benign_probe import (
    RAW_VOLUME_RE,
    _basename,
    _classify_event1,
    _event_data,
    _event_id,
)

SCENARIO = "T1006-1"
SOURCE_COMMIT = "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/p2_11f_t1006_attack_probe.json"))
    args = parser.parse_args()

    folder = args.root / "ttp_evtx" / SCENARIO
    files = sorted(folder.glob("*Sysmon*Operational.evtx"))
    if len(files) != 1:
        raise SystemExit(f"{SCENARIO}: expected exactly one Sysmon EVTX, got {len(files)}")

    event_ids: Counter[str] = Counter()
    parse_errors = 0
    raw_event1 = []
    event9 = []
    candidate_counts: Counter[str] = Counter()

    with Evtx(str(files[0])) as log:
        for record in log.records():
            try:
                xml = record.xml()
            except Exception:
                parse_errors += 1
                continue
            eid = _event_id(xml)
            event_ids[eid] += 1
            data = _event_data(xml)
            if eid == "1":
                image = data.get("Image", "")
                command_line = data.get("CommandLine", "")
                kinds = _classify_event1(image, command_line)
                for kind in kinds:
                    candidate_counts[kind] += 1
                if RAW_VOLUME_RE.search(command_line):
                    raw_event1.append({
                        "image": image,
                        "basename": _basename(image),
                        "command_line": command_line,
                        "candidate_kinds": kinds,
                        "parent_image": data.get("ParentImage", ""),
                        "parent_command_line": data.get("ParentCommandLine", ""),
                        "user": data.get("User", ""),
                        "utc_time": data.get("UtcTime", ""),
                    })
            elif eid == "9":
                event9.append({
                    "image": data.get("Image", ""),
                    "device": data.get("Device", ""),
                    "process_id": data.get("ProcessId", ""),
                    "utc_time": data.get("UtcTime", ""),
                })

    if parse_errors != 0:
        raise SystemExit(f"parse errors: {parse_errors}")
    if not raw_event1:
        raise SystemExit("expected at least one Sysmon Event 1 raw-volume-path command")

    result = {
        "schema": "breachscope.p2_11f_t1006_attack_probe.v1",
        "source_commit": SOURCE_COMMIT,
        "scenario_id": SCENARIO,
        "sysmon_file": files[0].name,
        "event_ids": dict(sorted(event_ids.items(), key=lambda kv: int(kv[0] or 0))),
        "parse_errors": parse_errors,
        "candidate_counts": dict(candidate_counts),
        "raw_volume_event1": raw_event1,
        "raw_access_read_event9": event9,
        "claim_boundary": {
            "note": "This probe re-reads the already-observed public Atomic-EVTX calibration scenario. It does not establish production detection quality."
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
