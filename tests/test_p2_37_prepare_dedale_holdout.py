from __future__ import annotations

import bz2
import importlib.util
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
EVALUATOR_PATH = ROOT / "scripts" / "evaluate_external_holdout.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = _load(ADAPTER_PATH, "p2_37_prepare_dedale_holdout")
evaluator = _load(EVALUATOR_PATH, "p2_37_evaluate_external_holdout")

START = "2025-01-06T00:00:00Z"
END = "2025-01-20T00:00:00Z"


def _row(
    *,
    timestamp: str,
    host: str,
    record_id: int,
    event_id: int,
    command_line: str = "",
    image: str = "",
    parent_image: str = "",
) -> dict:
    event_data: dict[str, object] = {}
    if command_line:
        event_data["CommandLine"] = command_line
    if image:
        event_data["Image"] = image
    if parent_image:
        event_data["ParentImage"] = parent_image

    process: dict[str, object] = {}
    if command_line:
        process["command_line"] = command_line
    if image:
        process["executable"] = image
    if parent_image:
        process["parent"] = {"executable": parent_image}

    return {
        "@timestamp": timestamp,
        "agent": {"type": "winlogbeat"},
        "event": {
            "code": event_id,
            "provider": "Microsoft-Windows-Sysmon",
        },
        "host": {"name": host},
        "process": process,
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer_name": host,
            "event_id": event_id,
            "provider_name": "Microsoft-Windows-Sysmon",
            "record_id": record_id,
            "event_data": event_data,
        },
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_normalize_is_label_blind_and_emits_frozen_windows_shape(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    rows = [
        _row(
            timestamp="2025-01-05T23:59:59Z",
            host="OUTSIDE.breach.local",
            record_id=1,
            event_id=1,
            command_line="outside.exe",
        ),
        _row(
            timestamp="2025-01-06T00:00:01Z",
            host="CLIENT1.breach.local",
            record_id=100,
            event_id=1,
            command_line="cmd.exe /c whoami",
            image=r"C:\Windows\System32\cmd.exe",
            parent_image=r"C:\Windows\explorer.exe",
        ),
        _row(
            timestamp="2025-01-07T00:00:01Z",
            host="CLIENT2.breach.local",
            record_id=101,
            event_id=1,
            command_line="powershell.exe -encodedcommand QUJDREVGR0g=",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_image=r"C:\Windows\explorer.exe",
        ),
    ]
    _write_jsonl(source / "day.jsonl", rows)

    corpus = tmp_path / "normalized.jsonl"
    identity_map = tmp_path / "identity.jsonl"
    result = adapter.normalize_corpus(
        winlogbeat_root=source,
        out_corpus=corpus,
        out_identity_map=identity_map,
        start=START,
        end=END,
    )

    assert result["status"] == "PASS"
    assert result["detection_rules_executed"] is False
    assert result["labels_read"] is False
    assert result["source_rows"] == 3
    assert result["outside_window_rows"] == 1
    assert result["selected_rows"] == 2

    normalized = _read_jsonl(corpus)
    identities = _read_jsonl(identity_map)
    assert len(normalized) == len(identities) == 2
    assert all("label" not in row for row in normalized)
    assert all(
        "malicious" not in json.dumps(row).casefold()
        for row in normalized
    )

    first = normalized[0]
    assert first["Hostname"] == "CLIENT1.breach.local"
    assert first["SourceName"] == "Microsoft-Windows-Sysmon"
    assert first["EventID"] == "1"
    assert first["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert first["RecordNumber"] == "100"
    assert first["Image"] == r"C:\Windows\System32\cmd.exe"
    assert first["CommandLine"] == "cmd.exe /c whoami"

    event = evaluator._record_to_event(first)
    assert event.host == "CLIENT1.breach.local"
    assert event.source == "Microsoft-Windows-Sysmon"
    assert str(event.event_id) == "1"
    assert event.command_line == "cmd.exe /c whoami"
    assert event.raw["canonical"]["process"]["executable"] == (
        r"C:\Windows\System32\cmd.exe"
    )


def test_provider_identity_uses_windows_record_identity() -> None:
    base = _row(
        timestamp="2025-01-08T15:07:55.919Z",
        host="CLIENT2.breach.local",
        record_id=4104297,
        event_id=11,
    )
    same = json.loads(json.dumps(base))
    changed = json.loads(json.dumps(base))
    changed["winlog"]["record_id"] = 4104298

    assert adapter.provider_identity(base) == adapter.provider_identity(same)
    assert adapter.provider_identity(base) != adapter.provider_identity(changed)


def test_provider_identity_preserves_zero_event_and_record_ids() -> None:
    row = _row(
        timestamp="2025-01-07T17:38:06.407Z",
        host="CLIENT1.breach.local",
        record_id=0,
        event_id=0,
    )

    payload = adapter._provider_identity_payload(row)
    assert payload["record_id"] == "0"
    assert payload["event_id"] == "0"
    assert adapter.normalize_winlogbeat_row(row)["EventID"] == "0"
    assert adapter.normalize_winlogbeat_row(row)["RecordNumber"] == "0"

    fallback = json.loads(json.dumps(row))
    fallback["winlog"]["event_id"] = None
    assert adapter._provider_identity_payload(fallback)["event_id"] == "0"
    assert adapter.provider_identity(fallback) == adapter.provider_identity(row)


def test_bind_labels_maps_class1_ignore_and_exact_complement(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    rows = [
        _row(
            timestamp="2025-01-06T00:00:01Z",
            host="CLIENT1.breach.local",
            record_id=100,
            event_id=1,
            command_line="benign.exe",
        ),
        _row(
            timestamp="2025-01-07T00:00:01Z",
            host="CLIENT2.breach.local",
            record_id=101,
            event_id=1,
            command_line="malicious.exe",
        ),
        _row(
            timestamp="2025-01-08T00:00:01Z",
            host="CLIENT2.breach.local",
            record_id=102,
            event_id=11,
        ),
    ]
    _write_jsonl(source / "day.jsonl", rows)

    corpus = tmp_path / "normalized.jsonl"
    identity_map = tmp_path / "identity.jsonl"
    adapter.normalize_corpus(
        winlogbeat_root=source,
        out_corpus=corpus,
        out_identity_map=identity_map,
        start=START,
        end=END,
    )

    normalized = _read_jsonl(corpus)
    index = tmp_path / "index.jsonl"
    index_rows = []
    for record_index, row in enumerate(normalized, 1):
        index_rows.append(
            {
                "event_key": evaluator.event_key(row),
                "source_file": corpus.name,
                "record_index": record_index,
                "identity": evaluator.event_identity_payload(row),
            }
        )
    _write_jsonl(index, index_rows)

    label_dir = tmp_path / "labels" / "clients_1_and_2"
    _write_jsonl(label_dir / adapter.CLASS1_NAME, [rows[1]])
    _write_jsonl(
        label_dir / adapter.CLASS1_AND_2_NAME,
        [rows[1], rows[2]],
    )

    labels = tmp_path / "labels.jsonl"
    result = adapter.bind_labels(
        evaluator_index=index,
        identity_map=identity_map,
        winlogbeat_labels_dir=label_dir,
        out_labels=labels,
        start=START,
        end=END,
    )

    assert result["status"] == "PASS"
    assert result["detection_rules_executed"] is False
    assert result["selected_events"] == 3
    assert result["malicious_class_1"] == 1
    assert result["combined_class_1_and_2"] == 2
    assert result["ignored_derived_class_2"] == 1
    assert result["benign_complement"] == 1

    output = _read_jsonl(labels)
    assert [row["label"] for row in output] == [
        "benign",
        "malicious",
        "ignore",
    ]
    assert [row["event_key"] for row in output] == [
        row["event_key"] for row in index_rows
    ]
    records = evaluator.load_corpus_records(
        {
            "files": [
                {
                    "path": corpus.name,
                    "sha256": adapter._sha256_file(corpus),
                    "format": "jsonl",
                }
            ]
        },
        tmp_path,
    )
    evaluator.require_complete_labels(
        records,
        evaluator.load_labels(labels),
    )


def test_bind_labels_fails_closed_when_provider_label_is_not_in_corpus(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    selected = _row(
        timestamp="2025-01-06T00:00:01Z",
        host="CLIENT1.breach.local",
        record_id=100,
        event_id=1,
    )
    missing = _row(
        timestamp="2025-01-07T00:00:01Z",
        host="CLIENT2.breach.local",
        record_id=999,
        event_id=1,
    )
    _write_jsonl(source / "day.jsonl", [selected])

    corpus = tmp_path / "normalized.jsonl"
    identity_map = tmp_path / "identity.jsonl"
    adapter.normalize_corpus(
        winlogbeat_root=source,
        out_corpus=corpus,
        out_identity_map=identity_map,
        start=START,
        end=END,
    )
    index = tmp_path / "index.jsonl"
    normalized = _read_jsonl(corpus)
    _write_jsonl(
        index,
        [
            {
                "event_key": evaluator.event_key(normalized[0]),
                "record_index": 1,
            }
        ],
    )

    label_dir = tmp_path / "labels" / "clients_1_and_2"
    _write_jsonl(label_dir / adapter.CLASS1_NAME, [missing])
    _write_jsonl(label_dir / adapter.CLASS1_AND_2_NAME, [missing])

    with pytest.raises(
        adapter.DedalePreparationError,
        match="not an exact subset",
    ):
        adapter.bind_labels(
            evaluator_index=index,
            identity_map=identity_map,
            winlogbeat_labels_dir=label_dir,
            out_labels=tmp_path / "labels.jsonl",
            start=START,
            end=END,
        )


def test_bind_labels_rejects_class1_missing_from_class1_and_2(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    selected = _row(
        timestamp="2025-01-06T00:00:01Z",
        host="CLIENT1.breach.local",
        record_id=100,
        event_id=1,
    )
    _write_jsonl(source / "day.jsonl", [selected])

    corpus = tmp_path / "normalized.jsonl"
    identity_map = tmp_path / "identity.jsonl"
    adapter.normalize_corpus(
        winlogbeat_root=source,
        out_corpus=corpus,
        out_identity_map=identity_map,
        start=START,
        end=END,
    )
    normalized = _read_jsonl(corpus)
    index = tmp_path / "index.jsonl"
    _write_jsonl(
        index,
        [
            {
                "event_key": evaluator.event_key(normalized[0]),
                "record_index": 1,
            }
        ],
    )

    label_dir = tmp_path / "labels" / "clients_1_and_2"
    _write_jsonl(label_dir / adapter.CLASS1_NAME, [selected])
    _write_jsonl(label_dir / adapter.CLASS1_AND_2_NAME, [])

    with pytest.raises(
        adapter.DedalePreparationError,
        match="class_1 must be an exact subset of class_1_and_2",
    ):
        adapter.bind_labels(
            evaluator_index=index,
            identity_map=identity_map,
            winlogbeat_labels_dir=label_dir,
            out_labels=tmp_path / "labels.jsonl",
            start=START,
            end=END,
        )


def test_normalize_rejects_duplicate_provider_identity(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    duplicated = _row(
        timestamp="2025-01-06T00:00:01Z",
        host="CLIENT1.breach.local",
        record_id=100,
        event_id=1,
    )
    _write_jsonl(source / "day.jsonl", [duplicated, duplicated])

    with pytest.raises(
        adapter.DedalePreparationError,
        match="duplicate provider identity",
    ):
        adapter.normalize_corpus(
            winlogbeat_root=source,
            out_corpus=tmp_path / "normalized.jsonl",
            out_identity_map=tmp_path / "identity.jsonl",
            start=START,
            end=END,
        )


def test_inspect_window_derives_last_14_of_exactly_28_consecutive_utc_dates(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    first = datetime(2024, 12, 23, 12, 0, 0, tzinfo=timezone.utc)
    rows = []
    for offset in range(28):
        timestamp = (first + timedelta(days=offset)).isoformat().replace(
            "+00:00", "Z"
        )
        rows.append(
            _row(
                timestamp=timestamp,
                host="CLIENT1.breach.local",
                record_id=1000 + offset,
                event_id=1,
            )
        )
    _write_jsonl(source / "all.jsonl", rows)

    result = adapter.inspect_window(winlogbeat_root=source)

    assert result["status"] == "PASS"
    assert result["detection_rules_executed"] is False
    assert result["labels_read"] is False
    assert result["distinct_utc_dates"] == 28
    assert result["first_utc_date"] == "2024-12-23"
    assert result["last_utc_date"] == "2025-01-19"
    assert result["test_window_policy"] == (
        "LAST_14_OF_EXACTLY_28_CONSECUTIVE_UTC_DATES"
    )
    assert result["test_window_start"] == "2025-01-06T00:00:00+00:00"
    assert result["test_window_end_exclusive"] == "2025-01-20T00:00:00+00:00"


def test_inspect_window_fails_closed_if_source_is_not_exactly_28_days(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    first = datetime(2024, 12, 23, 12, 0, 0, tzinfo=timezone.utc)
    rows = []
    for offset in range(27):
        timestamp = (first + timedelta(days=offset)).isoformat().replace(
            "+00:00", "Z"
        )
        rows.append(
            _row(
                timestamp=timestamp,
                host="CLIENT1.breach.local",
                record_id=2000 + offset,
                event_id=1,
            )
        )
    _write_jsonl(source / "all.jsonl", rows)

    with pytest.raises(
        adapter.DedalePreparationError,
        match="exactly 28 distinct UTC dates",
    ):
        adapter.inspect_window(winlogbeat_root=source)


def test_normalize_streams_realistic_outer_zip_with_jsonl_bz2_member(
    tmp_path: Path,
) -> None:
    source_zip = tmp_path / "system_logs_winlogbeat.zip"
    row = _row(
        timestamp="2025-01-08T15:07:55.919Z",
        host="CLIENT2.breach.local",
        record_id=4104297,
        event_id=11,
    )
    payload = (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
    compressed = bz2.compress(payload)
    with zipfile.ZipFile(source_zip, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "daily_winlogbeat/D17_H15_2025-01-08T15_winlogbeat_F400.jsonl.bz2",
            compressed,
        )

    corpus = tmp_path / "normalized.jsonl"
    identity_map = tmp_path / "identity.jsonl"
    result = adapter.normalize_corpus(
        winlogbeat_root=source_zip,
        out_corpus=corpus,
        out_identity_map=identity_map,
        start=START,
        end=END,
    )

    assert result["source_data_files"] == 1
    assert result["source_rows"] == 1
    assert result["selected_rows"] == 1
    assert _read_jsonl(corpus)[0]["RecordNumber"] == "4104297"


def test_bind_labels_reads_only_clients_winlogbeat_from_realistic_label_zip(
    tmp_path: Path,
) -> None:
    source = tmp_path / "winlogbeat"
    malicious = _row(
        timestamp="2025-01-08T15:07:55.919Z",
        host="CLIENT2.breach.local",
        record_id=4104297,
        event_id=11,
    )
    related = _row(
        timestamp="2025-01-08T15:07:56.919Z",
        host="CLIENT2.breach.local",
        record_id=4104298,
        event_id=11,
    )
    benign = _row(
        timestamp="2025-01-08T15:07:57.919Z",
        host="CLIENT2.breach.local",
        record_id=4104299,
        event_id=11,
    )
    _write_jsonl(source / "day.jsonl", [malicious, related, benign])

    corpus = tmp_path / "normalized.jsonl"
    identity_map = tmp_path / "identity.jsonl"
    adapter.normalize_corpus(
        winlogbeat_root=source,
        out_corpus=corpus,
        out_identity_map=identity_map,
        start=START,
        end=END,
    )
    normalized = _read_jsonl(corpus)
    index = tmp_path / "index.jsonl"
    _write_jsonl(
        index,
        [
            {
                "event_key": evaluator.event_key(row),
                "record_index": i,
            }
            for i, row in enumerate(normalized, 1)
        ],
    )

    label_zip = tmp_path / "system_logs_labels.zip"
    def jsonl_bytes(rows: list[dict]) -> bytes:
        return "".join(
            json.dumps(row, ensure_ascii=False) + "\n" for row in rows
        ).encode("utf-8")

    with zipfile.ZipFile(label_zip, "w") as archive:
        archive.writestr(
            "system_labels/clients_1_and_2/malicious_events_class_1.jsonl",
            jsonl_bytes([malicious]),
        )
        archive.writestr(
            "system_labels/clients_1_and_2/malicious_events_class_1_and_2.jsonl",
            jsonl_bytes([malicious, related]),
        )
        archive.writestr(
            "system_labels/internal_server/malicious_events_class_1.jsonl",
            b'{"agent":{"type":"auditbeat"}}\n',
        )
        archive.writestr(
            "system_labels/internal_server/malicious_events_class_1_and_2.jsonl",
            b'{"agent":{"type":"auditbeat"}}\n',
        )

    out = tmp_path / "labels.jsonl"
    result = adapter.bind_labels(
        evaluator_index=index,
        identity_map=identity_map,
        winlogbeat_labels_dir=label_zip,
        out_labels=out,
        start=START,
        end=END,
    )
    assert result["malicious_class_1"] == 1
    assert result["combined_class_1_and_2"] == 2
    assert result["ignored_derived_class_2"] == 1
    assert result["benign_complement"] == 1
    assert [row["label"] for row in _read_jsonl(out)] == [
        "malicious",
        "ignore",
        "benign",
    ]
