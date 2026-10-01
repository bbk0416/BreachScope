#!/usr/bin/env python3
"""Parallel, label-blind P2-37 DEDALE window inspector.

This does not replace or modify the frozen adapter. It imports the frozen
adapter helpers and applies the same event-level validation/date parsing over
every Winlogbeat JSONL/JSONL.BZ2 member, partitioned across worker processes.
No labels or detection code are read or executed.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import importlib.util
import io
import json
import os
import zipfile
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "31bf09ada2f5f511f0eea8ff492732178d848233"


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _load_adapter(path: Path):
    spec = importlib.util.spec_from_file_location("p2_37_frozen_adapter", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load frozen adapter: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scan_names(args: tuple[str, str, list[str]]) -> dict[str, Any]:
    source_text, adapter_text, names = args
    source = Path(source_text)
    adapter_path = Path(adapter_text)
    if _git_blob_sha1(adapter_path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise RuntimeError("frozen adapter Git blob SHA-1 mismatch in worker")
    adapter = _load_adapter(adapter_path)

    rows = 0
    dates: set[str] = set()
    with zipfile.ZipFile(source) as archive:
        for name in names:
            with archive.open(name, "r") as binary:
                if name.casefold().endswith(".bz2"):
                    text_handle = bz2.open(binary, "rt", encoding="utf-8")
                else:
                    text_handle = io.TextIOWrapper(binary, encoding="utf-8")
                with text_handle as handle:
                    for line_number, line in enumerate(handle, 1):
                        text = line.strip()
                        if not text:
                            continue
                        row = adapter._decode_json_line(text, name, line_number)
                        adapter._require_winlogbeat(row)
                        day = adapter._parse_time(
                            row.get("@timestamp"), "event"
                        ).date().isoformat()
                        dates.add(day)
                        rows += 1
    return {"rows": rows, "dates": sorted(dates), "members": len(names)}


def _balanced_partitions(
    infos: list[zipfile.ZipInfo], workers: int
) -> list[list[str]]:
    bins: list[list[str]] = [[] for _ in range(workers)]
    loads = [0] * workers
    for info in sorted(infos, key=lambda item: (-item.file_size, item.filename)):
        idx = min(range(workers), key=lambda i: (loads[i], i))
        bins[idx].append(info.filename)
        loads[idx] += info.file_size
    return [names for names in bins if names]


def inspect_window_parallel(
    *, winlogbeat_root: Path, adapter_path: Path, workers: int
) -> dict[str, Any]:
    source = winlogbeat_root.resolve()
    adapter_path = adapter_path.resolve()
    if _git_blob_sha1(adapter_path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise RuntimeError("frozen adapter Git blob SHA-1 mismatch")
    adapter = _load_adapter(adapter_path)

    names = adapter._winlogbeat_source_names(source)
    if not source.is_file() or source.suffix.casefold() != ".zip":
        raise RuntimeError("parallel inspector currently requires a ZIP source")

    with zipfile.ZipFile(source) as archive:
        by_name = {info.filename: info for info in archive.infolist()}
        infos = [by_name[name] for name in names]

    worker_count = max(1, min(int(workers), len(infos)))
    partitions = _balanced_partitions(infos, worker_count)
    tasks = [
        (str(source), str(adapter_path), names_part)
        for names_part in partitions
    ]

    if worker_count == 1:
        partials = [_scan_names(tasks[0])]
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            partials = list(pool.map(_scan_names, tasks))

    rows = sum(int(item["rows"]) for item in partials)
    dates = sorted({day for item in partials for day in item["dates"]})
    if len(dates) != 28:
        raise RuntimeError(
            "DEDALE source must expose exactly 28 distinct UTC dates before "
            f"freezing the last-two-weeks window; observed={len(dates)}"
        )

    ordered = [datetime.fromisoformat(day).date() for day in dates]
    for previous, current in zip(ordered, ordered[1:]):
        if (current - previous).days != 1:
            raise RuntimeError(
                "DEDALE source UTC dates are not consecutive: "
                f"{previous.isoformat()} -> {current.isoformat()}"
            )

    test_dates = ordered[-14:]
    start_dt = datetime.combine(
        test_dates[0], datetime.min.time(), tzinfo=timezone.utc
    )
    end_dt = datetime.combine(
        test_dates[-1] + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    return {
        "status": "PASS",
        "detection_rules_executed": False,
        "labels_read": False,
        "source_data_files": len(names),
        "source_rows": rows,
        "distinct_utc_dates": len(ordered),
        "first_utc_date": ordered[0].isoformat(),
        "last_utc_date": ordered[-1].isoformat(),
        "test_window_policy": "LAST_14_OF_EXACTLY_28_CONSECUTIVE_UTC_DATES",
        "test_window_start": start_dt.isoformat(),
        "test_window_end_exclusive": end_dt.isoformat(),
        "workers": worker_count,
        "frozen_adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--winlogbeat-root", required=True)
    ap.add_argument(
        "--adapter",
        default=str(Path(__file__).with_name("p2_37_prepare_dedale_holdout.py")),
    )
    ap.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    return ap


def main() -> int:
    args = parser().parse_args()
    result = inspect_window_parallel(
        winlogbeat_root=Path(args.winlogbeat_root),
        adapter_path=Path(args.adapter),
        workers=args.workers,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
