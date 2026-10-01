from __future__ import annotations

import bz2
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
RESUMABLE = ROOT / "scripts" / "p2_37_normalize_dedale_resumable.py"
FAST = ROOT / "scripts" / "p2_37_normalize_dedale_fast_resumable.py"
EVIDENCE = ROOT / "external_baseline" / "p2_37_fast_normalization_evidence.yaml"

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
        ],
        "daily_winlogbeat/b.jsonl.bz2": [
            _row(
                timestamp="2025-01-07T00:00:01Z",
                host="CLIENT2",
                record_id=2,
                event_id=4688,
                command_line="powershell.exe -nop",
            ),
            _row(
                timestamp="2025-01-20T00:00:00Z",
                host="OUTSIDE2",
                record_id=3,
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
    *,
    prepare_only: bool = False,
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


def _run_fast(
    source: Path,
    work: Path,
    temp_root: Path,
    corpus: Path,
    identity: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(FAST),
            "--winlogbeat-root",
            str(source),
            "--adapter",
            str(ADAPTER),
            "--resumable-normalizer",
            str(RESUMABLE),
            "--work-dir",
            str(work),
            "--temp-root",
            str(temp_root),
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
            "--json-backend",
            "stdlib",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_fast_resumable_is_byte_identical_to_resumable(
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

    fast_work = tmp_path / "fast-work"
    fast_corpus = tmp_path / "fast-corpus.jsonl"
    fast_identity = tmp_path / "fast-identity.jsonl"
    fast = _run_fast(
        source,
        fast_work,
        tmp_path / "fast-temp",
        fast_corpus,
        fast_identity,
    )
    assert fast.returncode == 0, fast.stderr
    result = _last_json(fast.stdout)

    assert fast_corpus.read_bytes() == reference_corpus.read_bytes()
    assert fast_identity.read_bytes() == reference_identity.read_bytes()
    assert result["normalized_corpus_sha256"] == reference_result[
        "normalized_corpus_sha256"
    ]
    assert result["identity_map_sha256"] == reference_result[
        "identity_map_sha256"
    ]
    assert result["selected_rows"] == reference_result["selected_rows"]
    assert result["source_rows"] == reference_result["source_rows"]
    assert result["outside_window_rows"] == reference_result[
        "outside_window_rows"
    ]
    assert result["labels_read"] is False
    assert result["detection_rules_executed"] is False
    assert result["json_backend"] == "stdlib"
    assert result["seven_zip_enabled"] is False


def test_fast_resumable_reuses_existing_authoritative_markers(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.zip"
    _write_zip(source)
    work = tmp_path / "shared-work"

    prepared = _run_resumable(
        source,
        work,
        tmp_path / "unused-corpus.jsonl",
        tmp_path / "unused-identity.jsonl",
        prepare_only=True,
    )
    assert prepared.returncode == 0, prepared.stderr
    prepared_result = _last_json(prepared.stdout)
    assert prepared_result["committed_members"] == 2

    corpus = tmp_path / "corpus.jsonl"
    identity = tmp_path / "identity.jsonl"
    fast = _run_fast(
        source,
        work,
        tmp_path / "fast-temp",
        corpus,
        identity,
    )
    assert fast.returncode == 0, fast.stderr
    result = _last_json(fast.stdout)

    assert result["resumed_members"] == 2
    assert result["committed_members"] == 2
    assert len(list(work.glob("*.done.json"))) == 2


def test_actual_member_fast_equivalence_evidence_is_exact() -> None:
    row = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    actual = row["actual_source_equivalence"]

    assert row["status"] == "PRE_SCORING_ACCELERATION_EVIDENCE"
    assert row["boundary"]["labels_read"] is False
    assert row["boundary"]["detector_run"] is False
    assert actual["source_member_index"] == 152
    assert actual["source_rows"] == 1028001
    assert actual["selected_rows"] == 1028001
    assert actual["exact_match"] is True
    assert actual["canonical_corpus_sha256"] == actual[
        "accelerated_corpus_sha256"
    ]
    assert actual["canonical_identity_sha256"] == actual[
        "accelerated_identity_sha256"
    ]
    assert actual["canonical_corpus_size_bytes"] == actual[
        "accelerated_corpus_size_bytes"
    ]
    assert actual["canonical_identity_size_bytes"] == actual[
        "accelerated_identity_size_bytes"
    ]
    assert row["reuse_contract"]["existing_valid_markers_may_be_reused"] is True
    assert (
        row["claim_boundary"][
            "full_corpus_equivalence_is_not_claimed_before_full_run_completion"
        ]
        is True
    )
