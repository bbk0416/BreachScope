#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event(xml: str) -> dict[str, str]:
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    event_id = ""
    if system is not None:
        node = system.find("e:EventID", NS)
        if node is not None and node.text:
            event_id = node.text
    data: dict[str, str] = {"EventID": event_id}
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        for node in event_data.findall("e:Data", NS):
            name = node.attrib.get("Name", "")
            if name:
                data[name] = node.text or ""
    return data


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("evtx", type=Path)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()

    raw = args.evtx.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    events: list[dict[str, str]] = []
    parse_errors = 0

    with Evtx(str(args.evtx)) as log:
        for record in log.records():
            try:
                item = parse_event(record.xml())
            except Exception:
                parse_errors += 1
                continue
            if item.get("EventID") != "1":
                continue
            events.append({
                "UtcTime": item.get("UtcTime", ""),
                "ProcessGuid": item.get("ProcessGuid", ""),
                "ProcessId": item.get("ProcessId", ""),
                "Image": item.get("Image", ""),
                "CommandLine": item.get("CommandLine", ""),
                "User": item.get("User", ""),
                "ParentProcessGuid": item.get("ParentProcessGuid", ""),
                "ParentProcessId": item.get("ParentProcessId", ""),
                "ParentImage": item.get("ParentImage", ""),
                "ParentCommandLine": item.get("ParentCommandLine", ""),
            })

    def low(v: str) -> str:
        return v.lower()

    result = {
        "schema": "breachscope.p2_11i_t1021_001_1_event1_dump.v1",
        "source_repository": "arniki/atomic-evtx",
        "source_commit": "8de5fa8f158b4d72d1e3c6f07053162c90ee6238",
        "source_path": "ttp_evtx/T1021.001-1/T1021.001-1_Microsoft-Windows-Sysmon_Operational.evtx",
        "source_sha256": sha256,
        "event1_count": len(events),
        "parse_errors": parse_errors,
        "candidate_counts": {
            "image_mstsc": sum(low(e["Image"]).endswith("\\mstsc.exe") for e in events),
            "commandline_contains_mstsc": sum("mstsc" in low(e["CommandLine"]) for e in events),
            "commandline_contains_v_switch": sum("/v:" in low(e["CommandLine"]) for e in events),
            "image_mstsc_and_v_switch": sum(low(e["Image"]).endswith("\\mstsc.exe") and "/v:" in low(e["CommandLine"]) for e in events),
            "commandline_contains_3389": sum("3389" in low(e["CommandLine"]) for e in events),
            "rdp_text_any": sum(any(x in low(e["CommandLine"]) for x in ("mstsc", "/v:", "3389", "rdp")) for e in events),
        },
        "events": events,
    }
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("source_sha256", "event1_count", "parse_errors", "candidate_counts")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
