from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import setup_middleware
from api.services.analysis_service import AnalysisService
from api.services.upload_policy import (
    UploadBudget,
    UploadLimitError,
    stream_upload_to_path,
    validate_file_count,
)


class FakeUpload:
    def __init__(self, filename: str, payload: bytes):
        self.filename = filename
        self.payload = payload
        self.offset = 0
        self.read_sizes = []

    async def read(self, size: int = -1):
        self.read_sizes.append(size)
        if size < 0:
            raise AssertionError("whole-file read() is forbidden")
        if self.offset >= len(self.payload):
            return b""
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


def test_stream_writer_uses_bounded_reads(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_UPLOAD_CHUNK_BYTES", "4")
    monkeypatch.setenv("BS_UPLOAD_MAX_FILE_BYTES", "100")
    monkeypatch.setenv("BS_UPLOAD_MAX_TOTAL_BYTES", "100")

    upload = FakeUpload("sample.bin", b"abcdefghij")
    destination = tmp_path / "sample.bin"

    written = asyncio.run(
        stream_upload_to_path(
            upload,
            destination,
            UploadBudget(),
        )
    )

    assert written == 10
    assert destination.read_bytes() == b"abcdefghij"
    assert upload.read_sizes
    assert set(upload.read_sizes) == {4}


def test_per_file_limit_removes_partial_destination(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_UPLOAD_CHUNK_BYTES", "4")
    monkeypatch.setenv("BS_UPLOAD_MAX_FILE_BYTES", "6")
    monkeypatch.setenv("BS_UPLOAD_MAX_TOTAL_BYTES", "100")

    destination = tmp_path / "too-big.bin"

    with pytest.raises(UploadLimitError):
        asyncio.run(
            stream_upload_to_path(
                FakeUpload("too-big.bin", b"abcdefgh"),
                destination,
                UploadBudget(),
            )
        )

    assert not destination.exists()


def test_aggregate_limit_is_shared_across_files(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_UPLOAD_CHUNK_BYTES", "4")
    monkeypatch.setenv("BS_UPLOAD_MAX_FILE_BYTES", "100")
    monkeypatch.setenv("BS_UPLOAD_MAX_TOTAL_BYTES", "7")

    budget = UploadBudget()
    first = tmp_path / "one.bin"
    second = tmp_path / "two.bin"

    asyncio.run(
        stream_upload_to_path(
            FakeUpload("one.bin", b"abcd"),
            first,
            budget,
        )
    )

    with pytest.raises(UploadLimitError):
        asyncio.run(
            stream_upload_to_path(
                FakeUpload("two.bin", b"efgh"),
                second,
                budget,
            )
        )

    assert first.read_bytes() == b"abcd"
    assert not second.exists()


def test_file_count_limit(monkeypatch):
    monkeypatch.setenv("BS_UPLOAD_MAX_FILES", "2")
    with pytest.raises(UploadLimitError):
        validate_file_count([object(), object(), object()])


def test_content_length_fail_fast_returns_413(monkeypatch):
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "local")
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("BS_UPLOAD_MAX_REQUEST_BYTES", "10")

    app = FastAPI()
    setup_middleware(app)

    @app.post("/api/analyze")
    async def analyze():
        return {"ok": True}

    response = TestClient(app).post(
        "/api/analyze",
        content=b"01234567890",
    )
    assert response.status_code == 413
    assert response.json()["code"] == "UPLOAD_LIMIT_EXCEEDED"


def test_analysis_service_cleans_auto_workdir_on_upload_limit(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "cases"
    work = root / "case-upload-limit"
    work.mkdir(parents=True)

    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    monkeypatch.setenv("BS_UPLOAD_CHUNK_BYTES", "4")
    monkeypatch.setenv("BS_UPLOAD_MAX_FILE_BYTES", "6")
    monkeypatch.setenv("BS_UPLOAD_MAX_TOTAL_BYTES", "100")

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    with pytest.raises(UploadLimitError):
        asyncio.run(
            service.analyze(
                files=[FakeUpload("too-big.jsonl", b"abcdefgh")],
                use_repo_rules=True,
                min_severity="low",
                mitre_include="",
                mitre_exclude="",
                host_include="",
                redact=True,
                render_pdf=False,
                do_evtx=False,
                collect_evtx=False,
                collect_logs="",
                collect_hours=None,
                work_dir=None,
            )
        )

    assert not work.exists()


def test_p1_01_markers_present():
    import api.services.analysis_service as analysis_service
    import api.middleware as middleware

    analysis_source = open(
        analysis_service.__file__,
        "r",
        encoding="utf-8",
    ).read()
    middleware_source = open(
        middleware.__file__,
        "r",
        encoding="utf-8",
    ).read()

    assert "BREACHSCOPE_P1_01_STREAMING_UPLOAD_V1" in analysis_source
    assert "BREACHSCOPE_P1_01_REQUEST_LIMIT_V1" in middleware_source
    assert "content = await file.read()" not in analysis_source
