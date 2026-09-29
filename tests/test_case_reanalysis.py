from __future__ import annotations

from pathlib import Path

import pytest

from api.services.case_reanalysis import (
    CaseReanalysisError,
    close_reanalysis_uploads,
    retained_case_uploads,
)


def _managed_case_root(tmp_path: Path, monkeypatch) -> Path:
    cases_root = tmp_path / "cases"
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    root = cases_root / "retained"
    (root / "input").mkdir(parents=True)
    return root


def test_retained_case_uploads_stream_plaintext_input(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _managed_case_root(tmp_path, monkeypatch)
    nested = root / "input" / "nested"
    nested.mkdir()
    source_path = nested / "events.jsonl"
    source_path.write_bytes(b'{"event":"plain"}\n')

    sources = retained_case_uploads(root)
    try:
        assert [source.filename for source in sources] == [
            "nested__events.jsonl"
        ]
        chunks = []
        while True:
            chunk = sources[0].read(4)
            if not chunk:
                break
            chunks.append(chunk)
        assert b"".join(chunks) == b'{"event":"plain"}\n'
    finally:
        close_reanalysis_uploads(sources)

    assert source_path.read_bytes() == b'{"event":"plain"}\n'


def test_retained_case_uploads_reject_plaintext_encrypted_duplicate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _managed_case_root(tmp_path, monkeypatch)
    (root / "input" / "events.jsonl").write_bytes(b"plain")
    (root / "input" / "events.jsonl.enc").write_bytes(b"cipher")

    with pytest.raises(
        CaseReanalysisError,
        match="ambiguous plaintext/encrypted duplicates",
    ):
        retained_case_uploads(root)


def test_retained_case_uploads_requires_input_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _managed_case_root(tmp_path, monkeypatch)

    with pytest.raises(
        CaseReanalysisError,
        match="re-analyzable input artifacts",
    ):
        retained_case_uploads(root)
