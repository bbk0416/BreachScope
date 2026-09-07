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

    async def read(self, size: int = -1):
        if size < 0:
            raise AssertionError("whole-file read() is forbidden")
        if self.offset >= len(self.payload):
            return b""
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


def _run(service: AnalysisService, *, files, work_dir=None):
    return asyncio.run(
        service.analyze(
            files=files,
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
            work_dir=work_dir,
        )
    )


class FailingPipeline:
    def __init__(self, **kwargs):
        pass

    def run(self, **kwargs):
        raise RuntimeError("synthetic pipeline failure")


def test_failed_auto_analysis_removes_managed_case_directory(tmp_path, monkeypatch):
    cases_root = tmp_path / "cases"
    work = cases_root / "bs_case_failed"
    work.mkdir(parents=True)
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setattr(analysis_module, "Pipeline", FailingPipeline)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    upload = FakeUpload("Security.evtx", b"sensitive evidence")
    with pytest.raises(RuntimeError, match="synthetic pipeline failure"):
        _run(service, files=[upload])

    assert not work.exists()


def test_failed_explicit_workdir_preserves_existing_evidence_and_removes_upload(
    tmp_path,
    monkeypatch,
):
    cases_root = tmp_path / "cases"
    work = cases_root / "existing_case"
    work.mkdir(parents=True)
    existing = work / "existing.evtx"
    existing.write_bytes(b"pre-existing evidence")
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setattr(analysis_module, "Pipeline", FailingPipeline)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    upload = FakeUpload("Security.evtx", b"request evidence")
    with pytest.raises(RuntimeError, match="synthetic pipeline failure"):
        _run(service, files=[upload], work_dir=str(work))

    assert work.exists()
    assert existing.read_bytes() == b"pre-existing evidence"
    assert not (work / "Security.evtx").exists()


def test_generic_second_upload_failure_rolls_back_first_request_upload(
    tmp_path,
    monkeypatch,
):
    cases_root = tmp_path / "cases"
    work = cases_root / "existing_case"
    work.mkdir(parents=True)
    existing = work / "existing.evtx"
    existing.write_bytes(b"pre-existing evidence")
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    real_writer = analysis_module.stream_upload_to_path
    calls = 0

    async def fail_second(source, destination, budget, *, filename=None):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic disk failure")
        return await real_writer(
            source,
            destination,
            budget,
            filename=filename,
        )

    monkeypatch.setattr(analysis_module, "stream_upload_to_path", fail_second)

    files = [
        FakeUpload("first.evtx", b"first request evidence"),
        FakeUpload("second.evtx", b"second request evidence"),
    ]
    with pytest.raises(OSError, match="synthetic disk failure"):
        _run(service, files=files, work_dir=str(work))

    assert existing.read_bytes() == b"pre-existing evidence"
    assert not (work / "first.evtx").exists()
    assert not (work / "second.evtx").exists()


def test_p2_08f_marker_present():
    source = open(analysis_module.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P2_08F_FAILED_ANALYSIS_EVIDENCE_CLEANUP_V1" in source
