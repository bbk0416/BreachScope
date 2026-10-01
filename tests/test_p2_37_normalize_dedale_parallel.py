from __future__ import annotations

import bz2
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
PARALLEL_PATH = ROOT / "scripts" / "p2_37_normalize_dedale_parallel.py"

START = "2025-01-06T00:00:00Z"
END = "2025-01-20T00:00:00Z"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = _load(ADAPTER_PATH, "p2_37_parallel_normalization_adapter")


def _row(
    *,
    timestamp: str,
    host: str,
    record_id: int,
    event_id: int = 1,
    command_line: str = "",
) -> dict:
    event_data = {"CommandLine": command_line} if command_line else {}
    return {
        "@timestamp": timestamp,
        "agent": {"type": "winlogbeat"},
        "event": {
            "code": event_id,
            "provider": "Microsoft-Windows-Sysmon",
        },
        "host": {"name": host},
        "process": {"command_line": command_line} if command_line else {},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer_name": host,
            "event_id": event_id,
            "provider_name": "Microsoft-Windows-Sysmon",
            "record_id": record_id,
            "event_data": event_data,
        },
    }


def _payload(rows: list[dict]) -> bytes:
    raw = "".join(
        json.dumps(row, ensure_ascii=False) + "\n"
        for row in rows
    ).encode("utf-8")
    return bz2.compress(raw)


def _write_zip(path: Path, members: dict[str, list[dict]]) -> None:
    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as archive:
        for name, rows in members.items():
            archive.writestr(name, _payload(rows))


def _run_parallel(
    source: Path,
    corpus: Path,
    identity: Path,
    *,
    workers: int = 2,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(PARALLEL_PATH),
            "--winlogbeat-root",
            str(source),
            "--adapter",
            str(ADAPTER_PATH),
            "--out-corpus",
            str(corpus),
            "--out-identity-map",
            str(identity),
            "--start",
            START,
            "--end",
            END,
            "--workers",
            str(workers),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_parallel_normalization_is_byte_identical_to_frozen_serial(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(
        source,
        {
            "daily_winlogbeat/a.jsonl.bz2": [
                _row(
                    timestamp="2025-01-05T23:59:59Z",
                    host="OUTSIDE",
                    record_id=1,
                ),
                _row(
                    timestamp="2025-01-06T00:00:01Z",
                    host="CLIENT1",
                    record_id=2,
                    command_line="cmd.exe /c whoami",
                ),
            ],
            "daily_winlogbeat/b.jsonl.bz2": [
                _row(
                    timestamp="2025-01-07T00:00:01Z",
                    host="CLIENT2",
                    record_id=3,
                    command_line="powershell.exe -nop",
                ),
                _row(
                    timestamp="2025-01-20T00:00:00Z",
                    host="OUTSIDE2",
                    record_id=4,
                ),
            ],
            "daily_winlogbeat/c.jsonl.bz2": [
                _row(
                    timestamp="2025-01-19T23:59:59Z",
                    host="CLIENT3",
                    record_id=5,
                ),
            ],
        },
    )

    serial_corpus = tmp_path / "serial-corpus.jsonl"
    serial_identity = tmp_path / "serial-identity.jsonl"
    serial = adapter.normalize_corpus(
        winlogbeat_root=source,
        out_corpus=serial_corpus,
        out_identity_map=serial_identity,
        start=START,
        end=END,
    )

    parallel_corpus = tmp_path / "parallel-corpus.jsonl"
    parallel_identity = tmp_path / "parallel-identity.jsonl"
    proc = _run_parallel(
        source,
        parallel_corpus,
        parallel_identity,
        workers=2,
    )
    assert proc.returncode == 0, proc.stderr
    parallel = json.loads(proc.stdout)

    assert parallel_corpus.read_bytes() == serial_corpus.read_bytes()
    assert parallel_identity.read_bytes() == serial_identity.read_bytes()
    assert parallel["normalized_corpus_sha256"] == serial[
        "normalized_corpus_sha256"
    ]
    assert parallel["identity_map_sha256"] == serial["identity_map_sha256"]

    for key in (
        "status",
        "detection_rules_executed",
        "labels_read",
        "window_start",
        "window_end",
        "source_data_files",
        "selected_source_files",
        "source_rows",
        "outside_window_rows",
        "selected_rows",
    ):
        assert parallel[key] == serial[key]

    assert parallel["workers"] == 2
    assert parallel["frozen_adapter_git_blob_sha1"] == (
        "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
    )


def test_parallel_normalization_fails_closed_on_duplicate_provider_identity(
    tmp_path: Path,
) -> None:
    source = tmp_path / "duplicates.zip"
    duplicate = _row(
        timestamp="2025-01-06T00:00:01Z",
        host="CLIENT1",
        record_id=100,
    )
    _write_zip(
        source,
        {
            "daily_winlogbeat/a.jsonl.bz2": [duplicate],
            "daily_winlogbeat/b.jsonl.bz2": [duplicate],
        },
    )

    with pytest.raises(
        adapter.DedalePreparationError,
        match="duplicate provider identity",
    ):
        adapter.normalize_corpus(
            winlogbeat_root=source,
            out_corpus=tmp_path / "serial-corpus.jsonl",
            out_identity_map=tmp_path / "serial-identity.jsonl",
            start=START,
            end=END,
        )

    parallel_corpus = tmp_path / "parallel-corpus.jsonl"
    parallel_identity = tmp_path / "parallel-identity.jsonl"
    proc = _run_parallel(
        source,
        parallel_corpus,
        parallel_identity,
        workers=2,
    )
    assert proc.returncode != 0
    assert "duplicate provider identity" in proc.stderr
    assert not parallel_corpus.exists()
    assert not parallel_identity.exists()


def test_parallel_normalization_validates_outside_window_rows_too(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bad-outside.zip"
    bad = _row(
        timestamp="2025-01-05T12:00:00Z",
        host="OUTSIDE",
        record_id=10,
    )
    bad["agent"]["type"] = "auditbeat"
    _write_zip(
        source,
        {"daily_winlogbeat/a.jsonl.bz2": [bad]},
    )

    proc = _run_parallel(
        source,
        tmp_path / "corpus.jsonl",
        tmp_path / "identity.jsonl",
        workers=1,
    )
    assert proc.returncode != 0
    assert "not Winlogbeat" in proc.stderr
