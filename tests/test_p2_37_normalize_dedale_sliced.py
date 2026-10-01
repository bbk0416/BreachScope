from __future__ import annotations

import bz2
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
RESUMABLE = ROOT / "scripts" / "p2_37_normalize_dedale_resumable.py"
SLICED = ROOT / "scripts" / "p2_37_normalize_dedale_sliced.py"

START = "2025-01-06T00:00:00Z"
END = "2025-01-20T00:00:00Z"


def _row(
    *,
    timestamp: str,
    host: str,
    record_id: int,
    event_id: int,
    command_line: str,
) -> dict:
    return {
        "@timestamp": timestamp,
        "agent": {"type": "winlogbeat"},
        "event": {
            "code": event_id,
            "provider": "Microsoft-Windows-Sysmon",
        },
        "host": {"name": host},
        "process": {"command_line": command_line},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer_name": host,
            "event_id": event_id,
            "provider_name": "Microsoft-Windows-Sysmon",
            "record_id": record_id,
            "event_data": {"CommandLine": command_line},
        },
    }


def _write_zip(path: Path) -> None:
    members = {
        "daily_winlogbeat/a.jsonl.bz2": [
            _row(
                timestamp="2025-01-05T23:59:59Z",
                host="OUTSIDE",
                record_id=0,
                event_id=0,
                command_line="zero.exe",
            ),
            _row(
                timestamp="2025-01-06T00:00:01Z",
                host="CLIENT1",
                record_id=1,
                event_id=0,
                command_line="cmd.exe /c whoami",
            ),
            _row(
                timestamp="2025-01-06T00:00:02Z",
                host="CLIENT1",
                record_id=2,
                event_id=4688,
                command_line="powershell.exe -nop",
            ),
        ],
        "daily_winlogbeat/b.jsonl.bz2": [
            _row(
                timestamp="2025-01-07T00:00:01Z",
                host="CLIENT2",
                record_id=3,
                event_id=1,
                command_line="rundll32.exe a.dll,Entry",
            ),
            _row(
                timestamp="2025-01-19T23:59:59Z",
                host="CLIENT2",
                record_id=4,
                event_id=0,
                command_line="eventzero.exe",
            ),
            _row(
                timestamp="2025-01-20T00:00:00Z",
                host="OUTSIDE2",
                record_id=5,
                event_id=1,
                command_line="outside.exe",
            ),
        ],
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, rows in members.items():
            raw = "".join(
                json.dumps(row, ensure_ascii=False) + "\n"
                for row in rows
            ).encode("utf-8")
            archive.writestr(name, bz2.compress(raw))


def _last_json(stdout: str) -> dict:
    lines = [line for line in stdout.splitlines() if line.strip()]
    return json.loads(lines[-1])


def _run_resumable(
    source: Path,
    work: Path,
    corpus: Path,
    identity: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(RESUMABLE),
            "--winlogbeat-root",
            str(source),
            "--adapter",
            str(ADAPTER),
            "--work-dir",
            str(work),
            "--out-corpus",
            str(corpus),
            "--out-identity-map",
            str(identity),
            "--start",
            START,
            "--end",
            END,
            "--workers",
            "1",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _run_sliced(
    source: Path,
    work: Path,
    slice_root: Path,
    *,
    max_rows: int = 1,
    max_seconds: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SLICED),
            "--winlogbeat-root",
            str(source),
            "--adapter",
            str(ADAPTER),
            "--resumable-normalizer",
            str(RESUMABLE),
            "--work-dir",
            str(work),
            "--slice-root",
            str(slice_root),
            "--start",
            START,
            "--end",
            END,
            "--max-seconds",
            str(max_seconds),
            "--max-rows",
            str(max_rows),
            "--json-backend",
            "stdlib",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_sliced_resume_merges_byte_identically_to_resumable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(source)

    reference_work = tmp_path / "reference-work"
    reference_corpus = tmp_path / "reference-corpus.jsonl"
    reference_identity = tmp_path / "reference-identity.jsonl"
    reference = _run_resumable(
        source,
        reference_work,
        reference_corpus,
        reference_identity,
    )
    assert reference.returncode == 0, reference.stderr
    reference_result = _last_json(reference.stdout)

    sliced_work = tmp_path / "sliced-work"
    slice_root = tmp_path / "slice-state"

    committed = 0
    for _ in range(20):
        proc = _run_sliced(
            source,
            sliced_work,
            slice_root,
            max_rows=1,
        )
        assert proc.returncode == 0, proc.stderr
        result = _last_json(proc.stdout)
        assert result["status"] == "PASS"
        assert result["labels_read"] is False
        assert result["detection_rules_executed"] is False
        assert result["rows_processed_this_invocation"] <= 1
        committed = int(result["committed_members"])
        if committed == 2:
            break
    assert committed == 2
    assert len(list(sliced_work.glob("*.done.json"))) == 2

    corpus = tmp_path / "sliced-corpus.jsonl"
    identity = tmp_path / "sliced-identity.jsonl"
    merged = _run_resumable(
        source,
        sliced_work,
        corpus,
        identity,
    )
    assert merged.returncode == 0, merged.stderr
    merged_result = _last_json(merged.stdout)

    assert merged_result["resumed_members"] == 2
    assert corpus.read_bytes() == reference_corpus.read_bytes()
    assert identity.read_bytes() == reference_identity.read_bytes()
    assert merged_result["normalized_corpus_sha256"] == reference_result[
        "normalized_corpus_sha256"
    ]
    assert merged_result["identity_map_sha256"] == reference_result[
        "identity_map_sha256"
    ]


def test_sliced_resume_fails_closed_if_committed_slice_changes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(source)
    work = tmp_path / "work"
    slice_root = tmp_path / "slice-state"

    first = _run_sliced(
        source,
        work,
        slice_root,
        max_rows=1,
    )
    assert first.returncode == 0, first.stderr
    first_result = _last_json(first.stdout)
    assert first_result["committed_members"] == 0

    member_dir = slice_root / "000000"
    state = json.loads(
        (member_dir / "state.json").read_text(encoding="utf-8")
    )
    assert len(state["slices"]) == 1
    corpus_slice = member_dir / "slice-000000.corpus"
    corpus_slice.write_bytes(corpus_slice.read_bytes() + b"tamper\n")

    resumed = _run_sliced(
        source,
        work,
        slice_root,
        max_rows=1,
    )
    assert resumed.returncode != 0
    assert "corpus slice" in resumed.stderr
    assert not (work / "000000.done.json").exists()


def test_sliced_state_preserves_zero_event_id_contract(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(source)
    work = tmp_path / "work"
    slice_root = tmp_path / "slice-state"

    for _ in range(10):
        proc = _run_sliced(
            source,
            work,
            slice_root,
            max_rows=1,
        )
        assert proc.returncode == 0, proc.stderr
        if (work / "000000.done.json").exists():
            break

    marker = json.loads(
        (work / "000000.done.json").read_text(encoding="utf-8")
    )
    assert marker["source_rows"] == 3
    assert marker["outside_window_rows"] == 1
    assert marker["selected_rows"] == 2
    assert marker["adapter_git_blob_sha1"] == (
        "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
    )
