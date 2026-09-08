from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import api.routers.cases as cases_router
import api.services.case_history as case_history_module
from api.services.case_history import CaseHistoryService


def _row(case_id: str, work_dir: Path, stamp: str) -> dict:
    return {
        "case_id": case_id,
        "created_at": stamp,
        "updated_at": stamp,
        "work_dir": str(work_dir),
        "status": "completed",
        "finding_count": 1,
        "risk_score": 10,
        "risk_level": "low",
        "hosts": [],
        "techniques": [],
        "artifacts": {},
    }


def _service(tmp_path: Path, monkeypatch, rows: list[dict]) -> CaseHistoryService:
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    index_path = tmp_path / "case_history.json"
    index_path.write_text(
        json.dumps({"version": 1, "cases": rows}),
        encoding="utf-8",
    )
    return CaseHistoryService(index_path=index_path)


def test_delete_case_keeps_record_when_directory_delete_fails(tmp_path, monkeypatch):
    work = tmp_path / "cases" / "case_fail"
    work.mkdir(parents=True)
    service = _service(
        tmp_path,
        monkeypatch,
        [_row("case-fail", work, "2026-01-01T00:00:00Z")],
    )

    def fail_delete(path, *args, **kwargs):
        raise PermissionError("simulated delete failure")

    monkeypatch.setattr(case_history_module.shutil, "rmtree", fail_delete)

    result = service.delete_case("case-fail", remove_files=True)

    assert result == {
        "case_id": "case-fail",
        "deleted": False,
        "removed_files": False,
        "reason": "file_removal_failed",
    }
    assert work.exists()
    assert service.get_case("case-fail")["case_id"] == "case-fail"


def test_delete_case_removes_record_only_after_directory_is_gone(tmp_path, monkeypatch):
    work = tmp_path / "cases" / "case_ok"
    work.mkdir(parents=True)
    service = _service(
        tmp_path,
        monkeypatch,
        [_row("case-ok", work, "2026-01-01T00:00:00Z")],
    )

    result = service.delete_case("case-ok", remove_files=True)

    assert result == {
        "case_id": "case-ok",
        "deleted": True,
        "removed_files": True,
    }
    assert not work.exists()
    with pytest.raises(KeyError):
        service.get_case("case-ok")


def test_delete_case_can_remove_stale_record_when_workdir_is_already_missing(tmp_path, monkeypatch):
    work = tmp_path / "cases" / "already_missing"
    service = _service(
        tmp_path,
        monkeypatch,
        [_row("case-stale", work, "2026-01-01T00:00:00Z")],
    )

    result = service.delete_case("case-stale", remove_files=True)

    assert result["deleted"] is True
    assert result["removed_files"] is False
    with pytest.raises(KeyError):
        service.get_case("case-stale")


def test_prune_keeps_only_case_whose_file_delete_failed(tmp_path, monkeypatch):
    ok_work = tmp_path / "cases" / "case_ok"
    fail_work = tmp_path / "cases" / "case_fail"
    ok_work.mkdir(parents=True)
    fail_work.mkdir(parents=True)
    service = _service(
        tmp_path,
        monkeypatch,
        [
            _row("case-ok", ok_work, "2026-01-02T00:00:00Z"),
            _row("case-fail", fail_work, "2026-01-01T00:00:00Z"),
        ],
    )

    real_rmtree = case_history_module.shutil.rmtree

    def selective_delete(path, *args, **kwargs):
        if Path(path) == fail_work:
            raise PermissionError("simulated prune failure")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(case_history_module.shutil, "rmtree", selective_delete)

    result = service.prune_cases(keep_last=0, dry_run=False, remove_files=True)

    assert result["candidate_count"] == 2
    assert result["removed_case_records"] == 1
    assert result["removed_files"] == 1
    assert result["failed_file_deletions"] == 1
    assert not ok_work.exists()
    assert fail_work.exists()
    assert service.get_case("case-fail")["case_id"] == "case-fail"
    with pytest.raises(KeyError):
        service.get_case("case-ok")


def test_delete_route_returns_conflict_when_evidence_delete_did_not_finish(monkeypatch):
    class FakeService:
        def delete_case(self, case_id, remove_files=True):
            return {
                "case_id": case_id,
                "deleted": False,
                "removed_files": False,
                "reason": "file_removal_failed",
            }

    class FakeAudit:
        def record(self, *args, **kwargs):
            return None

    monkeypatch.setattr(cases_router, "_service", lambda: FakeService())
    monkeypatch.setattr(cases_router, "AuditLogService", FakeAudit)
    request = Request(
        {
            "type": "http",
            "method": "DELETE",
            "path": "/cases/case-fail",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(cases_router.delete_case("case-fail", request, remove_files=True))

    assert exc_info.value.status_code == 409
    assert "이력을 유지" in str(exc_info.value.detail)


def test_p2_08j_marker_present():
    source = Path(case_history_module.__file__).read_text(encoding="utf-8")
    assert "BREACHSCOPE_P2_08J_CASE_DELETE_OUTCOME_CONSISTENCY_V1" in source
