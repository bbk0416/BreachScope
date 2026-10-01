from __future__ import annotations

import bz2
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
PARALLEL_PATH = ROOT / "scripts" / "p2_37_normalize_dedale_parallel.py"
RESUMABLE_PATH = ROOT / "scripts" / "p2_37_normalize_dedale_resumable.py"

START = "2025-01-06T00:00:00Z"
END = "2025-01-20T00:00:00Z"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = _load(ADAPTER_PATH, "p2_37_resumable_adapter")


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


def _write_zip(path: Path) -> None:
    members = {
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
    }
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
            "2",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _run_resumable(
    source: Path,
    work_dir: Path,
    corpus: Path,
    identity: Path,
    *,
    prepare_only: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(RESUMABLE_PATH),
        "--winlogbeat-root",
        str(source),
        "--adapter",
        str(ADAPTER_PATH),
        "--work-dir",
        str(work_dir),
        "--out-corpus",
        str(corpus),
        "--out-identity-map",
        str(identity),
        "--start",
        START,
        "--end",
        END,
        "--workers",
        "2",
    ]
    if prepare_only:
        cmd.append("--prepare-only")
    return subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _last_json(stdout: str) -> dict:
    lines = [line for line in stdout.splitlines() if line.strip()]
    return json.loads(lines[-1])


def test_resumable_normalization_is_byte_identical_to_parallel(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(source)

    reference_corpus = tmp_path / "reference-corpus.jsonl"
    reference_identity = tmp_path / "reference-identity.jsonl"
    reference = _run_parallel(
        source,
        reference_corpus,
        reference_identity,
    )
    assert reference.returncode == 0, reference.stderr
    reference_result = _last_json(reference.stdout)

    work_dir = tmp_path / "resume-work"
    corpus = tmp_path / "resumable-corpus.jsonl"
    identity = tmp_path / "resumable-identity.jsonl"

    prepared = _run_resumable(
        source,
        work_dir,
        corpus,
        identity,
        prepare_only=True,
    )
    assert prepared.returncode == 0, prepared.stderr
    prepare_result = _last_json(prepared.stdout)
    assert prepare_result["prepare_only"] is True
    assert prepare_result["committed_members"] == 3
    assert not corpus.exists()
    assert not identity.exists()
    assert len(list(work_dir.glob("*.done.json"))) == 3

    resumed = _run_resumable(
        source,
        work_dir,
        corpus,
        identity,
    )
    assert resumed.returncode == 0, resumed.stderr
    result = _last_json(resumed.stdout)

    assert result["resumed_members"] == 3
    assert result["committed_members"] == 3
    assert corpus.read_bytes() == reference_corpus.read_bytes()
    assert identity.read_bytes() == reference_identity.read_bytes()
    assert result["normalized_corpus_sha256"] == reference_result[
        "normalized_corpus_sha256"
    ]
    assert result["identity_map_sha256"] == reference_result[
        "identity_map_sha256"
    ]
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
        assert result[key] == reference_result[key]


def test_resumable_reprocesses_chunk_when_marker_hash_no_longer_matches(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(source)
    work_dir = tmp_path / "resume-work"
    corpus = tmp_path / "corpus.jsonl"
    identity = tmp_path / "identity.jsonl"

    prepared = _run_resumable(
        source,
        work_dir,
        corpus,
        identity,
        prepare_only=True,
    )
    assert prepared.returncode == 0, prepared.stderr

    damaged = work_dir / "000001.corpus.jsonl"
    original = damaged.read_bytes()
    damaged.write_bytes(original + b"damage\n")

    resumed = _run_resumable(
        source,
        work_dir,
        corpus,
        identity,
    )
    assert resumed.returncode == 0, resumed.stderr
    result = _last_json(resumed.stdout)

    assert result["resumed_members"] == 2
    assert damaged.read_bytes() == original

    reference_corpus = tmp_path / "reference-corpus.jsonl"
    reference_identity = tmp_path / "reference-identity.jsonl"
    reference = _run_parallel(
        source,
        reference_corpus,
        reference_identity,
    )
    assert reference.returncode == 0, reference.stderr
    assert corpus.read_bytes() == reference_corpus.read_bytes()
    assert identity.read_bytes() == reference_identity.read_bytes()


def test_resumable_marker_is_commit_point_not_raw_chunk_presence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(source)
    work_dir = tmp_path / "resume-work"
    work_dir.mkdir()
    stale_corpus = work_dir / "000000.corpus.jsonl"
    stale_identity = work_dir / "000000.identity.jsonl"
    stale_corpus.write_bytes(b"partial")
    stale_identity.write_bytes(b"partial")

    corpus = tmp_path / "corpus.jsonl"
    identity = tmp_path / "identity.jsonl"
    proc = _run_resumable(
        source,
        work_dir,
        corpus,
        identity,
    )
    assert proc.returncode == 0, proc.stderr
    result = _last_json(proc.stdout)

    assert result["resumed_members"] == 0
    assert len(list(work_dir.glob("*.done.json"))) == 3

    reference_corpus = tmp_path / "reference-corpus.jsonl"
    reference_identity = tmp_path / "reference-identity.jsonl"
    reference = _run_parallel(
        source,
        reference_corpus,
        reference_identity,
    )
    assert reference.returncode == 0, reference.stderr
    assert corpus.read_bytes() == reference_corpus.read_bytes()
    assert identity.read_bytes() == reference_identity.read_bytes()
