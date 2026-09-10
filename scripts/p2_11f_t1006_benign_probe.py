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
RAW_VOLUME_RE = re.compile(r"\\{2}\.\\[A-Za-z]:", re.IGNORECASE)
FILESTREAM_RE = re.compile(r"(?:System\.)?IO\.FileStream|\bFileStream\b", re.IGNORECASE)
OPEN_RE = re.compile(r"\bOpen\b", re.IGNORECASE)
READ_RE = re.compile(r"\bRead\b", re.IGNORECASE)

EXPECTED_RECORDS = 732_200
EXPECTED_CHUNKS = 11_894


def _event_id(xml: str) -> str:
    match = EVENT_ID_RE.search(xml)
    return match.group(1) if match else ""


def _event_data(xml: str) -> dict[str, str]:
    return {name: html.unescape(value) for name, value in DATA_RE.findall(xml)}


def _basename(value: str) -> str:
    return ntpath.basename(value.strip().strip('"')).lower()


def _classify_event1(image: str, command_line: str) -> list[str]:
    hits: list[str] = []
    if not RAW_VOLUME_RE.search(command_line):
        return hits
    hits.append("raw_volume_path_any")
    if _basename(image) in {"powershell.exe", "pwsh.exe"}:
        hits.append("powershell_raw_volume")
    if FILESTREAM_RE.search(command_line):
        hits.append("filestream_raw_volume")
        if OPEN_RE.search(command_line) and READ_RE.search(command_line):
            hits.append("filestream_open_read_raw_volume")
    return hits


def _selftest() -> None:
    positive = r'powershell.exe -c $f = New-Object IO.FileStream("\\.\C:", [IO.FileMode]::Open, [IO.FileAccess]::Read)'
    kinds = set(_classify_event1(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", positive))
    expected = {
        "raw_volume_path_any",
        "powershell_raw_volume",
        "filestream_raw_volume",
        "filestream_open_read_raw_volume",
    }
    if kinds != expected:
        raise SystemExit(f"candidate regex self-test failed: {sorted(kinds)}")
    if _classify_event1(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"powershell.exe -c Get-Content C:\Windows\win.ini",
    ):
        raise SystemExit("candidate regex negative self-test failed")


def _worker(path: str, worker_index: int, worker_count: int) -> dict[str, Any]:
    counters: Counter[str] = Counter()
    samples: dict[str, list[dict[str, str]]] = {
        "raw_volume_path_any": [],
        "powershell_raw_volume": [],
        "filestream_raw_volume": [],
        "filestream_open_read_raw_volume": [],
        "event9_raw_access_read": [],
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
                eid = _event_id(xml)
                if eid == "1":
                    counters["event1"] += 1
                    data = _event_data(xml)
                    image = data.get("Image", "")
                    command_line = data.get("CommandLine", "")
                    if _basename(image) in {"powershell.exe", "pwsh.exe"}:
                        counters["powershell_event1"] += 1
                    for kind in _classify_event1(image, command_line):
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
                elif eid == "9":
                    counters["event9"] += 1
                    data = _event_data(xml)
                    if len(samples["event9_raw_access_read"]) < 50:
                        samples["event9_raw_access_read"].append({
                            "image": data.get("Image", ""),
                            "device": data.get("Device", ""),
                            "process_id": data.get("ProcessId", ""),
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
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--out", type=Path, default=Path("out/p2_11f_t1006_benign_probe.json"))
    args = parser.parse_args()

    _selftest()
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
        "schema": "breachscope.p2_11f_t1006_benign_probe.v1",
        "scope": {
            "sysmon_records": combined["records"],
            "sysmon_chunks": EXPECTED_CHUNKS,
            "sysmon_event1": combined["event1"],
            "sysmon_event9": combined["event9"],
            "powershell_event1": combined["powershell_event1"],
            "parse_errors": parse_errors,
        },
        "candidate_counts": {
            "raw_volume_path_any": combined["raw_volume_path_any"],
            "powershell_raw_volume": combined["powershell_raw_volume"],
            "filestream_raw_volume": combined["filestream_raw_volume"],
            "filestream_open_read_raw_volume": combined["filestream_open_read_raw_volume"],
        },
        "samples": samples,
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "fresh_full_rulepack_fpr": "NOT_CLAIMED",
            "note": "Counts apply only to the pinned public benign-by-source-intent Sysmon corpus and these exact candidate predicates."
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
