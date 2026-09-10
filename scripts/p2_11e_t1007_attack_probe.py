#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from Evtx.Evtx import Evtx

from p2_11e_t1007_benign_probe import _args, _basename, _classify, _event_data, _event_id, _norm_args

SCENARIOS = ("T1007-1", "T1007-2")


def scan_file(path: Path) -> dict:
    event1 = 0
    parse_errors = 0
    interesting = []
    counts = {
        "sc_query_broad": 0,
        "sc_query_list_exact": 0,
        "sc_query_other": 0,
        "net_start_list_exact": 0,
        "net_start_named_service": 0,
    }
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml = record.xml()
            except Exception:
                parse_errors += 1
                continue
            if _event_id(xml) != "1":
                continue
            event1 += 1
            data = _event_data(xml)
            image = data.get("Image", "")
            cmd = data.get("CommandLine", "")
            kinds = _classify(image, cmd)
            if _basename(image) in {"sc.exe", "net.exe", "net1.exe"}:
                interesting.append({
                    "image": image,
                    "basename": _basename(image),
                    "command_line": cmd,
                    "normalized_args": _norm_args(_args(cmd)),
                    "candidate_kinds": kinds,
                    "parent_image": data.get("ParentImage", ""),
                    "parent_command_line": data.get("ParentCommandLine", ""),
                    "user": data.get("User", ""),
                    "utc_time": data.get("UtcTime", ""),
                })
            for kind in kinds:
                counts[kind] += 1
    return {
        "event1": event1,
        "parse_errors": parse_errors,
        "candidate_counts": counts,
        "interesting": interesting,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/p2_11e_t1007_attack_probe.json"))
    args = parser.parse_args()

    result = {
        "schema": "breachscope.p2_11e_t1007_attack_probe.v1",
        "source_commit": "8de5fa8f158b4d72d1e3c6f07053162c90ee6238",
        "scenarios": {},
    }
    for scenario in SCENARIOS:
        folder = args.root / "ttp_evtx" / scenario
        files = sorted(folder.glob("*Sysmon*Operational.evtx"))
        if len(files) != 1:
            raise SystemExit(f"{scenario}: expected exactly one Sysmon EVTX, got {len(files)}")
        result["scenarios"][scenario] = scan_file(files[0])
        if result["scenarios"][scenario]["parse_errors"] != 0:
            raise SystemExit(f"{scenario}: parse errors")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
