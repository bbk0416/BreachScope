from __future__ import annotations

import hashlib
import importlib.util
import json
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
SLICED_PATH = ROOT / "scripts" / "p2_37_normalize_dedale_sliced.py"
EVIDENCE = (
    ROOT
    / "external_baseline"
    / "p2_37_orjson_serialization_equivalence.yaml"
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = _load(ADAPTER_PATH, "p2_37_orjson_adapter")
sliced = _load(SLICED_PATH, "p2_37_orjson_sliced")


class _FakeOrjson:
    OPT_SORT_KEYS = 1

    @staticmethod
    def dumps(value, option=0):
        assert option == _FakeOrjson.OPT_SORT_KEYS
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


def _row() -> dict:
    return {
        "@timestamp": "2025-01-06T00:00:01Z",
        "agent": {"type": "winlogbeat"},
        "event": {
            "code": 0,
            "provider": "Dwminit",
        },
        "host": {"name": "CLIENT1"},
        "message": "zero event id – 한글",
        "process": {"command_line": "cmd.exe /c echo 테스트"},
        "winlog": {
            "channel": "Application",
            "computer_name": "CLIENT1",
            "event_id": 0,
            "provider_name": "Dwminit",
            "record_id": 1609,
            "event_data": {
                "Alpha": "β",
                "Count": 123,
                "Enabled": True,
            },
        },
    }


def test_orjson_slice_branch_emits_canonical_adapter_bytes(
    tmp_path: Path,
) -> None:
    row = _row()
    raw = (
        json.dumps(row, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")

    member_dir = tmp_path / "000000"
    member_dir.mkdir()
    (member_dir / "source.jsonl").write_bytes(raw)

    state = sliced._new_state(
        index=0,
        source_name="daily_winlogbeat/test.jsonl.bz2",
        source_file_size=123,
        start="2025-01-06T00:00:00Z",
        end="2025-01-20T00:00:00Z",
        raw_size=len(raw),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )
    start_dt, end_dt = adapter._window(
        "2025-01-06T00:00:00Z",
        "2025-01-20T00:00:00Z",
    )

    new_state, processed = sliced._process_slice(
        member_dir=member_dir,
        state=state,
        adapter=adapter,
        start_dt=start_dt,
        end_dt=end_dt,
        backend="orjson",
        orjson_module=_FakeOrjson,
        max_rows=10,
        deadline=time.monotonic() + 30,
    )

    assert processed == 1
    assert new_state["eof"] is True
    assert new_state["source_rows"] == 1
    assert new_state["outside_window_rows"] == 0
    assert new_state["selected_rows"] == 1

    normalized = adapter.normalize_winlogbeat_row(row)
    expected_corpus = adapter._json_bytes(normalized)
    expected_identity = adapter._json_bytes(
        {
            "provider_identity": adapter.provider_identity(row),
            "source_line": 1,
            "source_row_sha256": adapter._row_digest(row),
        }
    )

    corpus = member_dir / "slice-000000.corpus"
    identity = member_dir / "slice-000000.identity"
    assert corpus.read_bytes() == expected_corpus
    assert identity.read_bytes() == expected_identity
    assert new_state["slices"][0]["corpus_sha256"] == hashlib.sha256(
        expected_corpus
    ).hexdigest()
    assert new_state["slices"][0]["identity_sha256"] == hashlib.sha256(
        expected_identity
    ).hexdigest()


def test_actual_orjson_serialization_evidence_is_exact() -> None:
    row = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    actual = row["actual_source_equivalence"]

    assert row["status"] == (
        "PRE_SCORING_CANONICAL_SERIALIZATION_EQUIVALENCE"
    )
    assert row["boundary"]["labels_read"] is False
    assert row["boundary"]["detector_run"] is False
    assert actual["source_member_index"] == 152
    assert actual["source_rows"] == 1028001
    assert actual["selected_rows"] == 1028001
    assert actual["outside_window_rows"] == 0
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
    assert actual["compare_exit_code"] == 0
    assert actual["compare_stderr_bytes"] == 0
    assert row["compatibility"]["slice_state_schema_changed"] is False
    assert row["compatibility"]["member_marker_schema_changed"] is False
    assert row["compatibility"]["existing_stdlib_slices_may_be_reused"] is True
