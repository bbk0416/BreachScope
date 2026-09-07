from __future__ import annotations

import asyncio

import pytest

import api.services.analysis_service as analysis_module
from api.services.analysis_service import AnalysisService


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


def _run_analysis(service: AnalysisService, work, upload: FakeUpload):
    return asyncio.run(
        service.analyze(
            files=[upload],
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
            work_dir=str(work),
        )
    )


def test_analysis_retries_file_exists_race_without_consuming_upload(
    tmp_path,
    monkeypatch,
):
    work = tmp_path / "case"
    work.mkdir()
    captured = {}

    class FakePipeline:
        def __init__(self, **kwargs):
            pass

        def run(self, *, input_dir, out_prefix, **kwargs):
            captured["evidence"] = {
                path.name: path.read_bytes()
                for path in sorted(input_dir.glob("*.evtx"))
            }
            return out_prefix.with_suffix(".html"), 0

    monkeypatch.setattr(analysis_module, "Pipeline", FakePipeline)
    monkeypatch.setenv("BS_UPLOAD_CHUNK_BYTES", "4")
    monkeypatch.setenv("BS_UPLOAD_MAX_FILE_BYTES", "100")
    monkeypatch.setenv("BS_UPLOAD_MAX_TOTAL_BYTES", "100")

    real_writer = analysis_module.stream_upload_to_path
    attempted_paths = []

    async def race_once(source, destination, budget, *, filename=None):
        attempted_paths.append(destination)
        if len(attempted_paths) == 1:
            destination.write_bytes(b"racing evidence")
            raise FileExistsError(str(destination))
        return await real_writer(
            source,
            destination,
            budget,
            filename=filename,
        )

    monkeypatch.setattr(analysis_module, "stream_upload_to_path", race_once)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )
    upload = FakeUpload("Security.evtx", b"uploaded evidence")

    result = _run_analysis(service, work, upload)

    assert result["success"] is True
    assert [path.name for path in attempted_paths] == [
        "Security.evtx",
        "Security_2.evtx",
    ]
    assert captured["evidence"] == {
        "Security.evtx": b"racing evidence",
        "Security_2.evtx": b"uploaded evidence",
    }
    assert upload.offset == len(upload.payload)
    assert upload.read_sizes


def test_analysis_bounds_repeated_file_exists_retries_without_reading_source(
    tmp_path,
    monkeypatch,
):
    work = tmp_path / "case"
    work.mkdir()
    monkeypatch.setattr(analysis_module, "MAX_UPLOAD_NAME_COLLISION_RETRIES", 3)

    attempts = []

    async def always_collide(source, destination, budget, *, filename=None):
        attempts.append(destination)
        raise FileExistsError(str(destination))

    monkeypatch.setattr(analysis_module, "stream_upload_to_path", always_collide)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )
    upload = FakeUpload("Security.evtx", b"never consumed")

    with pytest.raises(FileExistsError):
        _run_analysis(service, work, upload)

    assert len(attempts) == 3
    assert upload.offset == 0
    assert upload.read_sizes == []


def test_p2_08e_marker_present():
    source = open(analysis_module.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P2_08E_RETRY_UPLOAD_NAME_COLLISION_V1" in source
