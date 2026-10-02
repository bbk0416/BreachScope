from __future__ import annotations

import bz2
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
RESUMABLE = ROOT / "scripts" / "p2_37_normalize_dedale_resumable.py"
AUTHORITY = ROOT / "scripts" / "p2_37_merge_normalized_resumable.py"
DEDUPE = ROOT / "scripts" / "p2_37_merge_normalized_semantic_dedupe.py"
AMENDMENT = (
    ROOT
    / "external_baseline"
    / "p2_37_semantic_duplicate_amendment.yaml"
)

START = "2025-01-06T00:00:00Z"
END = "2025-01-20T00:00:00Z"


def _row(
    *,
    timestamp: str,
    host: str,
    record_id: int,
    event_id: int,
    command_line: str,
    ephemeral_id: str,
    created: str,
) -> dict:
    return {
        "@timestamp": timestamp,
        "agent": {
            "type": "winlogbeat",
            "ephemeral_id": ephemeral_id,
        },
        "event": {
            "code": event_id,
            "provider": "Microsoft-Windows-Sysmon",
            "created": created,
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


def _write_source(
    path: Path,
    *,
    conflicting_duplicate: bool,
) -> None:
    first = _row(
        timestamp="2025-01-06T18:03:24.824Z",
        host="CLIENT3.breach.local",
        record_id=3718784,
        event_id=26,
        command_line="taskhostw.exe",
        ephemeral_id="aaa",
        created="2025-01-06T18:03:25.784Z",
    )
    second = _row(
        timestamp="2025-01-06T18:03:24.824Z",
        host="CLIENT3.breach.local",
        record_id=3718784,
        event_id=26,
        command_line=(
            "different.exe"
            if conflicting_duplicate
            else "taskhostw.exe"
        ),
        ephemeral_id="bbb",
        created="2025-01-07T08:21:13.912Z",
    )
    third = _row(
        timestamp="2025-01-07T00:00:01Z",
        host="CLIENT4.breach.local",
        record_id=10,
        event_id=1,
        command_line="unique.exe",
        ephemeral_id="ccc",
        created="2025-01-07T00:00:02Z",
    )

    members = {
        "daily_winlogbeat/a.jsonl.bz2": [first, second],
        "daily_winlogbeat/b.jsonl.bz2": [third],
    }
    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as archive:
        for name, rows in members.items():
            raw = "".join(
                json.dumps(row, ensure_ascii=False) + "\n"
                for row in rows
            ).encode("utf-8")
            archive.writestr(name, bz2.compress(raw))


def _last_json(stdout: str) -> dict:
    lines = [line for line in stdout.splitlines() if line.strip()]
    return json.loads(lines[-1])


def _prepare(
    source: Path,
    work: Path,
    unused_corpus: Path,
    unused_identity: Path,
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
            str(unused_corpus),
            "--out-identity-map",
            str(unused_identity),
            "--start",
            START,
            "--end",
            END,
            "--workers",
            "2",
            "--prepare-only",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _merge(
    work: Path,
    state: Path,
    corpus: Path,
    identity: Path,
    *,
    max_members: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(DEDUPE),
            "--work-dir",
            str(work),
            "--adapter",
            str(ADAPTER),
            "--merge-authority",
            str(AUTHORITY),
            "--state-dir",
            str(state),
            "--out-corpus",
            str(corpus),
            "--out-identity-map",
            str(identity),
            "--start",
            START,
            "--end",
            END,
            "--expected-members",
            "2",
            "--max-seconds",
            "30",
            "--max-members",
            str(max_members),
            "--json-backend",
            "stdlib",
            "--batch-size",
            "100",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_semantic_duplicate_keeps_first_exact_normalized_copy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_source(source, conflicting_duplicate=False)

    work = tmp_path / "work"
    prepared = _prepare(
        source,
        work,
        tmp_path / "unused-corpus.jsonl",
        tmp_path / "unused-identity.jsonl",
    )
    assert prepared.returncode == 0, prepared.stderr
    prep = _last_json(prepared.stdout)
    assert prep["selected_rows"] == 3
    assert prep["committed_members"] == 2

    corpus = tmp_path / "corpus.jsonl"
    identity = tmp_path / "identity.jsonl"
    state = tmp_path / "state"

    first = _merge(
        work,
        state,
        corpus,
        identity,
        max_members=1,
    )
    assert first.returncode == 0, first.stderr
    first_result = _last_json(first.stdout)
    assert first_result["status"] == "IN_PROGRESS"
    assert first_result["next_index"] == 1
    assert first_result["input_selected_rows"] == 2
    assert first_result["selected_rows"] == 1
    assert first_result["duplicate_rows"] == 1

    second = _merge(
        work,
        state,
        corpus,
        identity,
        max_members=1,
    )
    assert second.returncode == 0, second.stderr
    result = _last_json(second.stdout)

    assert result["status"] == "PASS"
    assert result["complete"] is True
    assert result["input_selected_rows"] == 3
    assert result["selected_rows"] == 2
    assert result["duplicate_rows"] == 1
    assert result["labels_read"] is False
    assert result["detection_rules_executed"] is False
    assert result["duplicate_policy"] == (
        "KEEP_FIRST_IF_NORMALIZED_BYTES_EXACTLY_IDENTICAL_ELSE_ABORT"
    )

    corpus_rows = [
        json.loads(line)
        for line in corpus.read_text(encoding="utf-8").splitlines()
    ]
    identity_rows = [
        json.loads(line)
        for line in identity.read_text(encoding="utf-8").splitlines()
    ]
    assert len(corpus_rows) == 2
    assert len(identity_rows) == 2
    assert [row["record_index"] for row in identity_rows] == [1, 2]
    assert identity_rows[0]["source_file"] == (
        "daily_winlogbeat/a.jsonl.bz2"
    )
    assert identity_rows[0]["source_line"] == 1


def test_semantic_duplicate_aborts_if_normalized_bytes_differ(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_source(source, conflicting_duplicate=True)

    work = tmp_path / "work"
    prepared = _prepare(
        source,
        work,
        tmp_path / "unused-corpus.jsonl",
        tmp_path / "unused-identity.jsonl",
    )
    assert prepared.returncode == 0, prepared.stderr

    corpus = tmp_path / "corpus.jsonl"
    identity = tmp_path / "identity.jsonl"
    proc = _merge(
        work,
        tmp_path / "state",
        corpus,
        identity,
        max_members=2,
    )
    assert proc.returncode != 0
    assert "different normalized bytes" in proc.stderr
    assert not corpus.exists()
    assert not identity.exists()


def test_semantic_duplicate_amendment_records_actual_source_evidence() -> None:
    row = yaml.safe_load(AMENDMENT.read_text(encoding="utf-8"))
    actual = row["actual_source_evidence"]
    policy = row["canonical_duplicate_policy"]

    assert row["status"] == "PRE_LABEL_PRE_SCORE_NORMALIZATION_AMENDMENT"
    assert row["boundary"]["labels_read_before_amendment"] is False
    assert row["boundary"]["detector_run_before_amendment"] is False
    assert actual["provider_identity"] == (
        "81b4753d3cb0681f161c3e01e74cf2346028c263674c77c03db865f51dea6875"
    )
    assert actual["source_member_index"] == 129
    assert actual["first_source_line"] == 25715
    assert actual["second_source_line"] == 25716
    assert actual["source_rows_byte_identical"] is False
    assert actual["normalized_rows_byte_identical"] is True
    assert actual["first_normalized_row_sha256"] == (
        "0978a388f037ccd741752980e762360e0cdd932b6273c596aac9b7efe1b5e1f3"
    )
    assert actual["second_normalized_row_sha256"] == (
        "0978a388f037ccd741752980e762360e0cdd932b6273c596aac9b7efe1b5e1f3"
    )
    assert policy["if_normalized_row_bytes_sha256_equal"] == "DROP_LATER_COPY"
    assert policy["if_normalized_row_bytes_sha256_different"] == (
        "ABORT_BEFORE_LABEL_BINDING"
    )
    assert (
        row["merge_state"]["previous_fail_closed_merge_state_may_be_reused"]
        is False
    )
