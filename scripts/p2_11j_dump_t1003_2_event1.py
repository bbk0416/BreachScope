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
    ap = argparse.ArgumentParser()
    ap.add_argument("evtx", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    raw = args.evtx.read_bytes()
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

    def text(e: dict[str, str]) -> str:
        return (e["Image"] + "\n" + e["CommandLine"] + "\n" + e["ParentCommandLine"]).lower()

    needles = {
        "networkprovider_any": "networkprovider",
        "networkprovider_order": "networkprovider\\order",
        "providerorder": "providerorder",
        "currentcontrolset_networkprovider": "currentcontrolset\\control\\networkprovider",
        "services_networkprovider": "services\\nppspy\\networkprovider",
        "nppspy": "nppspy",
    }
    candidate_counts = {k: sum(v in text(e) for e in events) for k, v in needles.items()}

    result = {
        "schema": "breachscope.p2_11j_t1003_2_event1_dump.v1",
        "source_repository": "arniki/atomic-evtx",
        "source_commit": "8de5fa8f158b4d72d1e3c6f07053162c90ee6238",
        "source_path": "ttp_evtx/T1003-2/T1003-2_Microsoft-Windows-Sysmon_Operational.evtx",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "event1_count": len(events),
        "parse_errors": parse_errors,
        "candidate_counts": candidate_counts,
        "events": events,
    }
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("source_sha256", "event1_count", "parse_errors", "candidate_counts")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
