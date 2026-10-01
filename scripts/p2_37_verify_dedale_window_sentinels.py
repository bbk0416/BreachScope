#!/usr/bin/env python3
"""Verify the amended P2-37 DEDALE window gate without labels or detection."""
from __future__ import annotations

import argparse
import bz2
import hashlib
import importlib.util
import json
import re
import zipfile
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "31bf09ada2f5f511f0eea8ff492732178d848233"
MEMBER_RE = re.compile(
    r"^daily_winlogbeat/D([0-9]+)_H([0-9]+)_([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2})_winlogbeat_F([0-9]+)\.jsonl\.bz2$"
)
EXPECTED_HOURS = list(range(24))


class WindowSentinelError(RuntimeError):
    pass


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _load_adapter(path: Path):
    if _git_blob_sha1(path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise WindowSentinelError("frozen adapter Git blob SHA-1 mismatch")
    spec = importlib.util.spec_from_file_location("p2_37_frozen_adapter_sentinel", path)
    if spec is None or spec.loader is None:
        raise WindowSentinelError(f"unable to load frozen adapter: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _metadata(source: Path) -> tuple[list[zipfile.ZipInfo], list[str]]:
    with zipfile.ZipFile(source) as archive:
        outer_files = [i for i in archive.infolist() if not i.is_dir()]
        data = [
            i for i in outer_files
            if i.filename.casefold().endswith((".jsonl", ".jsonl.bz2"))
        ]
    if len(outer_files) != 673:
        raise WindowSentinelError(f"outer file count mismatch: {len(outer_files)}")
    if len(data) != 672:
        raise WindowSentinelError(f"Winlogbeat data member count mismatch: {len(data)}")

    by_date: dict[str, list[tuple[zipfile.ZipInfo, int, int, int, int]]] = {}
    bad: list[str] = []
    for info in data:
        match = MEMBER_RE.match(info.filename)
        if not match:
            bad.append(info.filename)
            continue
        d_index, h_index, day, t_hour, f_index = match.groups()
        row = (info, int(d_index), int(h_index), int(t_hour), int(f_index))
        by_date.setdefault(day, []).append(row)
    if bad:
        raise WindowSentinelError(f"member name contract failed: {bad[:5]}")
    days = sorted(by_date)
    if len(days) != 28:
        raise WindowSentinelError(f"expected 28 dates, observed {len(days)}")

    parsed_days = [datetime.fromisoformat(day).date() for day in days]
    for idx, (day, parsed) in enumerate(zip(days, parsed_days), 1):
        rows = by_date[day]
        if len(rows) != 24:
            raise WindowSentinelError(f"{day}: expected 24 members, observed {len(rows)}")
        hours = sorted(row[2] for row in rows)
        t_hours = sorted(row[3] for row in rows)
        d_indexes = {row[1] for row in rows}
        if hours != EXPECTED_HOURS or t_hours != EXPECTED_HOURS:
            raise WindowSentinelError(f"{day}: hourly coverage mismatch")
        if d_indexes != {idx}:
            raise WindowSentinelError(f"{day}: D index mismatch: {sorted(d_indexes)}")
        for _, _, h_index, t_hour, _ in rows:
            if h_index != t_hour:
                raise WindowSentinelError(f"{day}: H index/T hour mismatch")
        if idx > 1 and (parsed - parsed_days[idx - 2]).days != 1:
            raise WindowSentinelError(
                f"UTC dates are not consecutive: {days[idx-2]} -> {day}"
            )

    sentinels: list[zipfile.ZipInfo] = []
    for day in days:
        candidates = [
            row[0] for row in by_date[day]
            if row[0].file_size > 14
        ]
        if not candidates:
            raise WindowSentinelError(f"{day}: no non-empty sentinel candidate")
        sentinels.append(min(candidates, key=lambda i: (i.file_size, i.filename)))
    return sentinels, days


def _scan_sentinel(args: tuple[str, str, str, str]) -> dict[str, Any]:
    source_text, adapter_text, member, expected_day = args
    source = Path(source_text)
    adapter = _load_adapter(Path(adapter_text))
    rows = 0
    seen_dates: set[str] = set()

    with zipfile.ZipFile(source) as archive:
        with archive.open(member, "r") as binary:
            if member.casefold().endswith(".bz2"):
                handle = bz2.open(binary, "rt", encoding="utf-8")
            else:
                import io
                handle = io.TextIOWrapper(binary, encoding="utf-8")
            with handle:
                for line_number, line in enumerate(handle, 1):
                    text = line.strip()
                    if not text:
                        continue
                    row = adapter._decode_json_line(text, member, line_number)
                    adapter._require_winlogbeat(row)
                    day = adapter._parse_time(
                        row.get("@timestamp"), "event"
                    ).date().isoformat()
                    if day != expected_day:
                        raise WindowSentinelError(
                            f"{member}:{line_number}: timestamp date {day} "
                            f"does not match filename date {expected_day}"
                        )
                    seen_dates.add(day)
                    rows += 1
    if rows == 0:
        raise WindowSentinelError(f"{member}: sentinel contains zero events")
    if seen_dates != {expected_day}:
        raise WindowSentinelError(
            f"{member}: unexpected sentinel dates {sorted(seen_dates)}"
        )
    return {"member": member, "expected_date": expected_day, "rows": rows}


def verify_window(*, source: Path, adapter: Path, workers: int) -> dict[str, Any]:
    sentinels, days = _metadata(source)
    selected: list[tuple[str, str, int]] = []
    for info in sentinels:
        match = MEMBER_RE.match(info.filename)
        assert match is not None
        selected.append((match.group(3), info.filename, info.file_size))

    worker_count = max(1, min(workers, len(selected)))
    tasks = [
        (str(source.resolve()), str(adapter.resolve()), member, day)
        for day, member, _ in selected
    ]
    if worker_count == 1:
        results = [_scan_sentinel(task) for task in tasks]
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            results = list(pool.map(_scan_sentinel, tasks))

    start_dt = datetime.combine(
        datetime.fromisoformat(days[-14]).date(),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    end_dt = datetime.combine(
        datetime.fromisoformat(days[-1]).date() + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    by_member = {row["member"]: row for row in results}
    return {
        "status": "PASS",
        "detection_rules_executed": False,
        "labels_read": False,
        "outer_file_count": 673,
        "source_data_files": 672,
        "distinct_utc_dates": 28,
        "members_per_date": 24,
        "first_utc_date": days[0],
        "last_utc_date": days[-1],
        "sentinel_count": len(selected),
        "sentinel_inner_bz2_bytes": sum(size for _, _, size in selected),
        "sentinel_rows": sum(by_member[member]["rows"] for _, member, _ in selected),
        "sentinels": [
            {
                "date": day,
                "member": member,
                "inner_bz2_bytes": size,
                "rows": by_member[member]["rows"],
            }
            for day, member, size in selected
        ],
        "test_window_policy": "LAST_14_OF_EXACTLY_28_CONSECUTIVE_UTC_DATES",
        "test_window_start": start_dt.isoformat(),
        "test_window_end_exclusive": end_dt.isoformat(),
        "frozen_adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
        "workers": worker_count,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument(
        "--adapter",
        default=str(Path(__file__).with_name("p2_37_prepare_dedale_holdout.py")),
    )
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()
    result = verify_window(
        source=Path(args.source),
        adapter=Path(args.adapter),
        workers=args.workers,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
