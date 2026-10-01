from __future__ import annotations

import bz2
import importlib.util
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
PARALLEL_PATH = ROOT / "scripts" / "p2_37_inspect_dedale_window_parallel.py"
EXPECTED_ADAPTER_BLOB = "31bf09ada2f5f511f0eea8ff492732178d848233"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _row(ts: str, record_id: int) -> dict:
    return {
        "@timestamp": ts,
        "agent": {"type": "winlogbeat"},
        "host": {"name": "host-a"},
        "event": {"code": "4688"},
        "winlog": {
            "channel": "Security",
            "record_id": record_id,
            "event_id": "4688",
        },
    }


def _make_zip(path: Path, *, days: int) -> None:
    start = datetime(2024, 12, 23, 12, tzinfo=timezone.utc)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for offset in range(days):
            ts = (start + timedelta(days=offset)).isoformat()
            payload = (json.dumps(_row(ts, offset + 1)) + "\n").encode()
            archive.writestr(
                f"daily_winlogbeat/day-{offset:02d}.jsonl.bz2",
                bz2.compress(payload),
            )


def test_parallel_window_inspector_matches_frozen_adapter(tmp_path: Path) -> None:
    source = tmp_path / "dedale.zip"
    _make_zip(source, days=28)

    adapter = _load(ADAPTER_PATH, "p2_37_adapter_test_equivalence")
    direct = adapter.inspect_window(winlogbeat_root=source)

    proc = subprocess.run(
        [
            sys.executable,
            str(PARALLEL_PATH),
            "--winlogbeat-root",
            str(source),
            "--adapter",
            str(ADAPTER_PATH),
            "--workers",
            "2",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    parallel = json.loads(proc.stdout)

    for key in (
        "status",
        "detection_rules_executed",
        "labels_read",
        "source_data_files",
        "source_rows",
        "distinct_utc_dates",
        "first_utc_date",
        "last_utc_date",
        "test_window_policy",
        "test_window_start",
        "test_window_end_exclusive",
    ):
        assert parallel[key] == direct[key]

    assert parallel["workers"] == 2
    assert parallel["frozen_adapter_git_blob_sha1"] == EXPECTED_ADAPTER_BLOB


def test_parallel_window_inspector_fails_closed_on_27_days(tmp_path: Path) -> None:
    source = tmp_path / "dedale-27.zip"
    _make_zip(source, days=27)

    proc = subprocess.run(
        [
            sys.executable,
            str(PARALLEL_PATH),
            "--winlogbeat-root",
            str(source),
            "--adapter",
            str(ADAPTER_PATH),
            "--workers",
            "2",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode != 0
    assert "exactly 28 distinct UTC dates" in proc.stderr


def test_parallel_inspector_pins_frozen_adapter_blob() -> None:
    module = _load(PARALLEL_PATH, "p2_37_parallel_hash_test")
    assert module.EXPECTED_ADAPTER_GIT_BLOB_SHA1 == EXPECTED_ADAPTER_BLOB
