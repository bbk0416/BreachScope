from __future__ import annotations

import bz2
import json
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
RESUMABLE = ROOT / "scripts" / "p2_37_normalize_dedale_resumable.py"
MERGE = ROOT / "scripts" / "p2_37_merge_normalized_resumable.py"
EVIDENCE = (
    ROOT
    / "external_baseline"
    / "p2_37_fast_final_merge_equivalence.yaml"
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


def _payload(rows: list[dict]) -> bytes:
    raw = "".join(
        json.dumps(row, ensure_ascii=False) + "\n"
        for row in rows
    ).encode("utf-8")
    return bz2.compress(raw)


def _write_source(path: Path, *, duplicate: bool = False) -> None:
    first = _row(
        timestamp="2025-01-06T00:00:01Z",
        host="CLIENT1",
        record_id=0,
        event_id=0,
        command_line="cmd.exe /c zero",
    )
    second = (
        first
        if duplicate
        else _row(
            timestamp="2025-01-07T00:00:01Z",
            host="CLIENT2",
            record_id=2,
            event_id=4688,
            command_line="powershell.exe -nop",
        )
    )
    third = _row(
        timestamp="2025-01-19T23:59:59Z",
        host="CLIENT3",
        record_id=3,
        event_id=1,
        command_line="rundll32.exe test.dll,Entry",
    )
    members = {
        "daily_winlogbeat/a.jsonl.bz2": [
            _row(
                timestamp="2025-01-05T23:59:59Z",
                host="OUTSIDE",
                record_id=99,
                event_id=1,
                command_line="outside.exe",
            ),
            first,
        ],
        "daily_winlogbeat/b.jsonl.bz2": [second],
        "daily_winlogbeat/c.jsonl.bz2": [third],
    }
    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as archive:
        for name, rows in members.items():
            archive.writestr(name, _payload(rows))


def _run_resumable(
    source: Path,
    work: Path,
    corpus: Path,
    identity: Path,
    *,
    prepare_only: bool,
) -> subprocess.CompletedProcess[str]:
    cmd = [
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


def _run_merge(
    work: Path,
    state_dir: Path,
    corpus: Path,
    identity: Path,
    *,
    expected_members: int = 3,
    max_members: int = 1,
    json_backend: str = "stdlib",
    insert_batch_size: int = 1,
    orjson_root: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [
            sys.executable,
            str(MERGE),
            "--work-dir",
            str(work),
            "--adapter",
            str(ADAPTER),
            "--state-dir",
            str(state_dir),
            "--out-corpus",
            str(corpus),
            "--out-identity-map",
            str(identity),
            "--start",
            START,
            "--end",
            END,
            "--expected-members",
            str(expected_members),
            "--max-seconds",
            "30",
            "--max-members",
            str(max_members),
            "--json-backend",
            json_backend,
            "--insert-batch-size",
            str(insert_batch_size),
        ]
    if orjson_root is not None:
        cmd.extend(["--orjson-root", str(orjson_root)])
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


def _prepare_two_workdirs(
    tmp_path: Path,
    *,
    duplicate: bool = False,
) -> tuple[Path, Path, Path]:
    source = tmp_path / "source.zip"
    _write_source(source, duplicate=duplicate)
    seed = tmp_path / "seed-work"
    prepared = _run_resumable(
        source,
        seed,
        tmp_path / "unused-corpus.jsonl",
        tmp_path / "unused-identity.jsonl",
        prepare_only=True,
    )
    assert prepared.returncode == 0, prepared.stderr
    ref = tmp_path / "reference-work"
    test = tmp_path / "test-work"
    shutil.copytree(seed, ref)
    shutil.copytree(seed, test)
    return source, ref, test


def test_resumable_final_merge_is_byte_identical_to_reference(
    tmp_path: Path,
) -> None:
    source, ref_work, test_work = _prepare_two_workdirs(tmp_path)

    ref_corpus = tmp_path / "reference-corpus.jsonl"
    ref_identity = tmp_path / "reference-identity.jsonl"
    reference = _run_resumable(
        source,
        ref_work,
        ref_corpus,
        ref_identity,
        prepare_only=False,
    )
    assert reference.returncode == 0, reference.stderr

    out_corpus = tmp_path / "merged-corpus.jsonl"
    out_identity = tmp_path / "merged-identity.jsonl"
    state_dir = tmp_path / "merge-state"

    results = []
    for _ in range(5):
        proc = _run_merge(
            test_work,
            state_dir,
            out_corpus,
            out_identity,
            max_members=1,
        )
        assert proc.returncode == 0, proc.stderr
        result = _last_json(proc.stdout)
        results.append(result)
        if result["complete"]:
            break

    assert results[-1]["complete"] is True
    assert results[-1]["next_index"] == 3
    assert results[-1]["labels_read"] is False
    assert results[-1]["detection_rules_executed"] is False
    assert out_corpus.read_bytes() == ref_corpus.read_bytes()
    assert out_identity.read_bytes() == ref_identity.read_bytes()

    final_again = _run_merge(
        test_work,
        state_dir,
        out_corpus,
        out_identity,
        max_members=1,
    )
    assert final_again.returncode == 0, final_again.stderr
    repeated = _last_json(final_again.stdout)
    assert repeated["complete"] is True
    assert repeated["next_index"] == 3


def test_final_merge_recovers_uncommitted_file_and_sqlite_writes(
    tmp_path: Path,
) -> None:
    source, ref_work, test_work = _prepare_two_workdirs(tmp_path)

    ref_corpus = tmp_path / "reference-corpus.jsonl"
    ref_identity = tmp_path / "reference-identity.jsonl"
    reference = _run_resumable(
        source,
        ref_work,
        ref_corpus,
        ref_identity,
        prepare_only=False,
    )
    assert reference.returncode == 0, reference.stderr

    out_corpus = tmp_path / "merged-corpus.jsonl"
    out_identity = tmp_path / "merged-identity.jsonl"
    state_dir = tmp_path / "merge-state"

    first = _run_merge(
        test_work,
        state_dir,
        out_corpus,
        out_identity,
        max_members=1,
    )
    assert first.returncode == 0, first.stderr
    first_result = _last_json(first.stdout)
    assert first_result["complete"] is False
    assert first_result["next_index"] == 1

    state = json.loads(
        (state_dir / "state.json").read_text(encoding="utf-8")
    )
    with (state_dir / "corpus.partial").open("ab") as handle:
        handle.write(b"uncommitted-corpus")
    with (state_dir / "identity.partial").open("ab") as handle:
        handle.write(b"uncommitted-identity")
    conn = sqlite3.connect(state_dir / "seen.sqlite3")
    try:
        conn.execute(
            """
            INSERT INTO seen(provider_identity, member_index)
            VALUES (?, ?)
            """,
            ("f" * 64, int(state["next_index"])),
        )
        conn.commit()
    finally:
        conn.close()

    for _ in range(5):
        proc = _run_merge(
            test_work,
            state_dir,
            out_corpus,
            out_identity,
            max_members=1,
        )
        assert proc.returncode == 0, proc.stderr
        result = _last_json(proc.stdout)
        if result["complete"]:
            break

    assert result["complete"] is True
    assert out_corpus.read_bytes() == ref_corpus.read_bytes()
    assert out_identity.read_bytes() == ref_identity.read_bytes()


def test_final_merge_fails_closed_on_duplicate_provider_identity(
    tmp_path: Path,
) -> None:
    _, _, test_work = _prepare_two_workdirs(
        tmp_path,
        duplicate=True,
    )
    state_dir = tmp_path / "merge-state"
    out_corpus = tmp_path / "corpus.jsonl"
    out_identity = tmp_path / "identity.jsonl"

    first = _run_merge(
        test_work,
        state_dir,
        out_corpus,
        out_identity,
        max_members=1,
    )
    assert first.returncode == 0, first.stderr

    second = _run_merge(
        test_work,
        state_dir,
        out_corpus,
        out_identity,
        max_members=1,
    )
    assert second.returncode != 0
    assert "duplicate provider identity" in second.stderr
    assert not out_corpus.exists()
    assert not out_identity.exists()


def _write_fake_orjson(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "orjson.py").write_text(
        """
import json
OPT_SORT_KEYS = 1
__version__ = "test-double"

def loads(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return json.loads(value)

def dumps(value, option=0):
    assert option == OPT_SORT_KEYS
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
""".lstrip(),
        encoding="utf-8",
        newline="\n",
    )


def test_fast_final_merge_is_byte_identical_and_state_compatible(
    tmp_path: Path,
) -> None:
    source, ref_work, test_work = _prepare_two_workdirs(tmp_path)

    ref_corpus = tmp_path / "reference-corpus.jsonl"
    ref_identity = tmp_path / "reference-identity.jsonl"
    reference = _run_resumable(
        source,
        ref_work,
        ref_corpus,
        ref_identity,
        prepare_only=False,
    )
    assert reference.returncode == 0, reference.stderr

    out_corpus = tmp_path / "fast-corpus.jsonl"
    out_identity = tmp_path / "fast-identity.jsonl"
    state_dir = tmp_path / "merge-state"
    fake_orjson = tmp_path / "fake-orjson"
    _write_fake_orjson(fake_orjson)

    first = _run_merge(
        test_work,
        state_dir,
        out_corpus,
        out_identity,
        max_members=1,
    )
    assert first.returncode == 0, first.stderr
    first_result = _last_json(first.stdout)
    assert first_result["next_index"] == 1

    for _ in range(5):
        proc = _run_merge(
            test_work,
            state_dir,
            out_corpus,
            out_identity,
            max_members=1,
            json_backend="orjson",
            insert_batch_size=2,
            orjson_root=fake_orjson,
        )
        assert proc.returncode == 0, proc.stderr
        result = _last_json(proc.stdout)
        if result["complete"]:
            break

    assert result["complete"] is True
    assert result["json_backend"] == "orjson"
    assert result["insert_batch_size"] == 2
    assert out_corpus.read_bytes() == ref_corpus.read_bytes()
    assert out_identity.read_bytes() == ref_identity.read_bytes()


def test_fast_final_merge_duplicate_batch_still_fails_closed(
    tmp_path: Path,
) -> None:
    _, _, test_work = _prepare_two_workdirs(
        tmp_path,
        duplicate=True,
    )
    state_dir = tmp_path / "merge-state"
    out_corpus = tmp_path / "corpus.jsonl"
    out_identity = tmp_path / "identity.jsonl"
    fake_orjson = tmp_path / "fake-orjson"
    _write_fake_orjson(fake_orjson)

    proc = _run_merge(
        test_work,
        state_dir,
        out_corpus,
        out_identity,
        max_members=3,
        json_backend="orjson",
        insert_batch_size=10,
        orjson_root=fake_orjson,
    )
    assert proc.returncode != 0
    assert "duplicate provider identity" in proc.stderr
    assert not out_corpus.exists()
    assert not out_identity.exists()


def test_actual_fast_final_merge_equivalence_evidence_is_exact() -> None:
    row = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    actual = row["actual_source_equivalence"]

    assert row["status"] == (
        "PRE_SCORING_FINAL_MERGE_ACCELERATION_EVIDENCE"
    )
    assert row["boundary"]["labels_read"] is False
    assert row["boundary"]["detector_run"] is False
    assert actual["normalized_member_index"] == 121
    assert actual["selected_rows"] == 650004
    assert actual["exact_match"] is True
    assert actual["canonical_identity_size_bytes"] == actual[
        "accelerated_identity_size_bytes"
    ]
    assert actual["canonical_identity_sha256"] == actual[
        "accelerated_identity_sha256"
    ]
    assert actual["accelerated_sqlite_seen_rows"] == 650004
    assert row["compatibility"]["current_final_merge_state_next_index"] == 122
    assert row["compatibility"]["existing_state_may_resume_with_fast_backend"] is True
