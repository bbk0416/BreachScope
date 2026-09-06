from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routers import analyze, report
from api.services.upload_policy import UploadLimitError
import api.services.path_boundary as path_boundary


INTERNAL_SECRET = r"C:\\private\\cases\\case-001\\evidence.json token=super-secret"


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("BS_AUDIT_ENABLED", "0")
    app = FastAPI()
    app.include_router(analyze.router, prefix="/api")
    app.include_router(report.router, prefix="/api")
    return TestClient(app)


def test_analyze_generic_500_does_not_expose_exception_detail(monkeypatch):
    async def fail(**kwargs):
        raise RuntimeError(INTERNAL_SECRET)

    monkeypatch.setattr(analyze.analysis_service, "analyze", fail)
    client = _client(monkeypatch)

    response = client.post("/api/analyze")

    assert response.status_code == 500
    assert response.json()["detail"] == "분석 중 내부 오류가 발생했습니다."
    assert INTERNAL_SECRET not in response.text


def test_analyze_permission_403_does_not_expose_exception_detail(monkeypatch):
    async def denied(**kwargs):
        raise PermissionError(INTERNAL_SECRET)

    monkeypatch.setattr(analyze.analysis_service, "analyze", denied)
    client = _client(monkeypatch)

    response = client.post("/api/analyze")

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "권한이 부족합니다. 관리자 권한으로 실행하거나 접근 가능한 로그만 선택하세요."
    )
    assert INTERNAL_SECRET not in response.text


def test_report_preview_generic_500_does_not_expose_exception_detail(monkeypatch):
    def fail(_work_dir):
        raise RuntimeError(INTERNAL_SECRET)

    monkeypatch.setattr(report, "load_preview", fail)
    client = _client(monkeypatch)

    response = client.get("/api/report-preview/unit-case")

    assert response.status_code == 500
    assert response.json()["detail"] == "리포트 미리보기 중 내부 오류가 발생했습니다."
    assert INTERNAL_SECRET not in response.text


def test_report_download_generic_500_does_not_expose_exception_detail(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError(INTERNAL_SECRET)

    monkeypatch.setattr(path_boundary, "validate_managed_work_dir", fail)
    client = _client(monkeypatch)

    response = client.get("/api/report/unit-case?file_type=html")

    assert response.status_code == 500
    assert response.json()["detail"] == "리포트 다운로드 중 내부 오류가 발생했습니다."
    assert INTERNAL_SECRET not in response.text


def test_report_preview_not_found_contract_is_preserved(monkeypatch):
    def missing(_work_dir):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(report, "load_preview", missing)
    client = _client(monkeypatch)

    response = client.get("/api/report-preview/unit-case")

    assert response.status_code == 404
    assert response.json()["detail"] == "미리보기용 report.json을 찾을 수 없습니다."


def test_analyze_upload_limit_413_contract_is_preserved(monkeypatch):
    async def limited(**kwargs):
        raise UploadLimitError("request exceeds configured upload limit")

    monkeypatch.setattr(analyze.analysis_service, "analyze", limited)
    client = _client(monkeypatch)

    response = client.post("/api/analyze")

    assert response.status_code == 413
    detail = response.json()["detail"]
    assert detail["code"] == "UPLOAD_LIMIT_EXCEEDED"
    assert detail["message"] == "request exceeds configured upload limit"
