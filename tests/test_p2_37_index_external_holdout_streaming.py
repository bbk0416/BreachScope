from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "scripts" / "evaluate_external_holdout.py"
STREAMING = ROOT / "scripts" / "p2_37_index_external_holdout_streaming.py"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row(
    *,
    timestamp: str,
    host: str,
    event_id: int,
    record_id: int,
    command_line: str,
) -> dict:
    return {
        "timestamp": timestamp,
        "host": host,
        "source": "Microsoft-Windows-Sysmon",
        "event_id": event_id,
        "user": "",
        "command_line": command_line,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_record_id": record_id,
        "raw": {
            "timestamp": timestamp,
            "host": host,
            "source": "Microsoft-Windows-Sysmon",
            "event_id": event_id,
            "command_line": command_line,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_record_id": record_id,
        },
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )


def _write_manifest(root: Path, names: list[str]) -> Path:
    manifest = {
        "schema": "breachscope.external_holdout.v1",
        "kind": "external_blind_holdout",
        "evaluation_class": "external_baseline",
        "protocol": {
            "independent_from_rule_authoring": True,
            "ground_truth_prepared_without_breachscope_findings": True,
            "final_holdout_seen_before_rule_freeze": False,
        },
        "files": [
            {
                "path": name,
                "sha256": _sha(root / name),
                "format": "jsonl",
            }
            for name in names
        ],
        "scenarios": [],
    }
    path = root / "manifest.yaml"
    path.write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )
    return path


def _run_reference(
    manifest: Path,
    corpus_root: Path,
    out: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(REFERENCE),
            "index",
            "--manifest",
            str(manifest),
            "--corpus-root",
            str(corpus_root),
            "--out",
            str(out),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _run_streaming(
    manifest: Path,
    corpus_root: Path,
    out: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(STREAMING),
            "--manifest",
            str(manifest),
            "--corpus-root",
            str(corpus_root),
            "--out",
            str(out),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_streaming_index_is_byte_identical_to_reference(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    _write_jsonl(
        a,
        [
            _row(
                timestamp="2025-01-06T00:00:01+00:00",
                host="CLIENT1",
                event_id=1,
                record_id=1,
                command_line="cmd.exe /c whoami",
            ),
            _row(
                timestamp="2025-01-06T00:00:02+00:00",
                host="CLIENT1",
                event_id=4688,
                record_id=2,
                command_line="powershell.exe -nop",
            ),
        ],
    )
    _write_jsonl(
        b,
        [
            _row(
                timestamp="2025-01-07T00:00:01+00:00",
                host="CLIENT2",
                event_id=1,
                record_id=1,
                command_line="rundll32.exe test.dll,Entry",
            )
        ],
    )
    manifest = _write_manifest(tmp_path, ["a.jsonl", "b.jsonl"])

    reference_out = tmp_path / "reference-index.jsonl"
    streaming_out = tmp_path / "streaming-index.jsonl"
    reference = _run_reference(manifest, tmp_path, reference_out)
    streaming = _run_streaming(manifest, tmp_path, streaming_out)

    assert reference.returncode == 0, reference.stderr
    assert streaming.returncode == 0, streaming.stderr
    assert streaming_out.read_bytes() == reference_out.read_bytes()

    result = json.loads(streaming.stdout)
    assert result["status"] == "PASS"
    assert result["events"] == 3
    assert result["source_files"] == 2
    assert result["index_sha256"] == _sha(reference_out)
    assert result["detection_rules_executed"] is False
    assert result["findings_emitted"] is False
    assert result["labels_read"] is False

    rows = [
        json.loads(line)
        for line in streaming_out.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["record_index"] for row in rows] == [1, 2, 1]
    assert [row["source_file"] for row in rows] == [
        "a.jsonl",
        "a.jsonl",
        "b.jsonl",
    ]


def test_streaming_index_matches_reference_duplicate_failure(
    tmp_path: Path,
) -> None:
    duplicate = _row(
        timestamp="2025-01-06T00:00:01+00:00",
        host="CLIENT1",
        event_id=1,
        record_id=100,
        command_line="cmd.exe /c whoami",
    )
    _write_jsonl(tmp_path / "a.jsonl", [duplicate])
    _write_jsonl(tmp_path / "b.jsonl", [duplicate])
    manifest = _write_manifest(tmp_path, ["a.jsonl", "b.jsonl"])

    reference_out = tmp_path / "reference-index.jsonl"
    streaming_out = tmp_path / "streaming-index.jsonl"
    reference = _run_reference(manifest, tmp_path, reference_out)
    streaming = _run_streaming(manifest, tmp_path, streaming_out)

    assert reference.returncode == 2
    assert streaming.returncode == 2
    assert "duplicate event identity in holdout corpus" in reference.stderr
    assert "duplicate event identity in holdout corpus" in streaming.stderr
    assert not reference_out.exists()
    assert not streaming_out.exists()


def test_streaming_index_verifies_manifest_hash_before_writing(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus.jsonl"
    _write_jsonl(
        corpus,
        [
            _row(
                timestamp="2025-01-06T00:00:01+00:00",
                host="CLIENT1",
                event_id=1,
                record_id=1,
                command_line="cmd.exe",
            )
        ],
    )
    manifest = _write_manifest(tmp_path, ["corpus.jsonl"])
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["files"][0]["sha256"] = "0" * 64
    manifest.write_text(
        yaml.safe_dump(data, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )

    out = tmp_path / "index.jsonl"
    proc = _run_streaming(manifest, tmp_path, out)
    assert proc.returncode == 2
    assert "corpus hash mismatch" in proc.stderr
    assert not out.exists()
