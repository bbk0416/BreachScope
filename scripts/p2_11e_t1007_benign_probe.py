#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import multiprocessing as mp
import ntpath
import re
from collections import Counter
from pathlib import Path
from typing import Any

from Evtx.Evtx import Evtx

EVENT_ID_RE = re.compile(r"<EventID(?:\s+[^>]*)?>(\d+)</EventID>", re.IGNORECASE)
DATA_RE = re.compile(r'<Data\s+Name="([^"]+)">(.*?)</Data>', re.IGNORECASE | re.DOTALL)

EXPECTED_RECORDS = 732_200
EXPECTED_CHUNKS = 11_894


def _event_id(xml: str) -> str:
    match = EVENT_ID_RE.search(xml)
    return match.group(1) if match else ""


def _event_data(xml: str) -> dict[str, str]:
    return {name: html.unescape(value) for name, value in DATA_RE.findall(xml)}


def _basename(value: str) -> str:
    return ntpath.basename(value.strip().strip('"')).lower()


def _args(command_line: str) -> str:
    value = command_line.strip()
    if not value:
        return ""
    if value.startswith('"'):
        end = value.find('"', 1)
        if end >= 0:
            return value[end + 1 :].strip()
    parts = value.split(None, 1)
    return parts[1].strip() if len(parts) == 2 else ""


def _norm_args(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"\s*=\s*", "=", value)
    return re.sub(r"\s+", " ", value)


def _classify(image: str, command_line: str) -> list[str]:
    exe = _basename(image)
    args = _norm_args(_args(command_line))
    hits: list[str] = []

    if exe == "sc.exe":
        if args == "query" or args.startswith("query "):
            hits.append("sc_query_broad")
        if args == "query" or args == "query state=all":
            hits.append("sc_query_list_exact")
        if args.startswith("query ") and args != "query state=all":
            hits.append("sc_query_other")

    if exe in {"net.exe", "net1.exe"}:
        if args == "start":
            hits.append("net_start_list_exact")
        elif args.startswith("start "):
            hits.append("net_start_named_service")

    return hits


def _worker(path: str, worker_index: int, worker_count: int) -> dict[str, Any]:
    counters: Counter[str] = Counter()
    samples: dict[str, list[dict[str, str]]] = {
        "sc_query_broad": [],
        "sc_query_list_exact": [],
        "sc_query_other": [],
        "net_start_list_exact": [],
        "net_start_named_service": [],
    }
    parse_errors = 0
    chunk_count = 0

    with Evtx(path) as log:
        for chunk_index, chunk in enumerate(log.chunks()):
            chunk_count += 1
            if chunk_index % worker_count != worker_index:
                continue
            for record in chunk.records():
                try:
                    xml = record.xml()
                except Exception:
                    parse_errors += 1
                    continue
                counters["records"] += 1
                if _event_id(xml) != "1":
                    continue
                counters["event1"] += 1
                data = _event_data(xml)
                image = data.get("Image", "")
                command_line = data.get("CommandLine", "")
                exe = _basename(image)
                if exe == "sc.exe":
                    counters["sc_process_create"] += 1
                if exe == "net.exe":
                    counters["net_process_create"] += 1
                if exe == "net1.exe":
                    counters["net1_process_create"] += 1
                for kind in _classify(image, command_line):
                    counters[kind] += 1
                    if len(samples[kind]) < 25:
                        samples[kind].append({
                            "image": image,
                            "command_line": command_line,
                            "user": data.get("User", ""),
                            "parent_image": data.get("ParentImage", ""),
                            "parent_command_line": data.get("ParentCommandLine", ""),
                            "utc_time": data.get("UtcTime", ""),
                        })

    return {
        "worker_index": worker_index,
        "chunk_count_seen": chunk_count,
        "parse_errors": parse_errors,
        "counters": dict(counters),
        "samples": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evtx", type=Path)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--out", type=Path, default=Path("p2_11e_t1007_benign_probe.json"))
    args = parser.parse_args()

    workers = max(1, args.workers)
    with mp.get_context("spawn").Pool(processes=workers) as pool:
        rows = pool.starmap(_worker, [(str(args.evtx), i, workers) for i in range(workers)])

    combined: Counter[str] = Counter()
    parse_errors = 0
    samples: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        combined.update(row["counters"])
        parse_errors += int(row["parse_errors"])
        for kind, items in row["samples"].items():
            samples.setdefault(kind, []).extend(items)
            samples[kind] = samples[kind][:50]

    chunk_counts = {int(row["chunk_count_seen"]) for row in rows}
    if chunk_counts != {EXPECTED_CHUNKS}:
        raise SystemExit(f"unexpected chunk count(s): {sorted(chunk_counts)}")
    if combined["records"] != EXPECTED_RECORDS:
        raise SystemExit(f"unexpected record count: {combined['records']}")
    if parse_errors != 0:
        raise SystemExit(f"parse errors: {parse_errors}")

    result = {
        "schema": "breachscope.p2_11e_t1007_benign_probe.v1",
        "scope": {
            "sysmon_records": combined["records"],
            "sysmon_chunks": EXPECTED_CHUNKS,
            "sysmon_event1": combined["event1"],
            "parse_errors": parse_errors,
        },
        "process_counts": {
            "sc_exe_event1": combined["sc_process_create"],
            "net_exe_event1": combined["net_process_create"],
            "net1_exe_event1": combined["net1_process_create"],
        },
        "candidate_counts": {
            "sc_query_broad": combined["sc_query_broad"],
            "sc_query_list_exact": combined["sc_query_list_exact"],
            "sc_query_other": combined["sc_query_other"],
            "net_start_list_exact": combined["net_start_list_exact"],
            "net_start_named_service": combined["net_start_named_service"],
        },
        "samples": samples,
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "note": "Counts apply only to the pinned public benign-by-source-intent Sysmon corpus and these exact command predicates."
        }
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
