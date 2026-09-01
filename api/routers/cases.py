"""분석 케이스 이력 API."""
from __future__ import annotations

from pathlib import Path
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse, JSONResponse

from api.services.case_history import CaseHistoryService
from api.services.audit_log import AuditLogService, actor_from_request
from api.services.report_preview import load_preview

router = APIRouter()

class CaseWorkflowUpdate(BaseModel):
    """Analyst-owned case workflow fields.

    Generated evidence fields are deliberately excluded so a triage update cannot
    alter the analysis result, artifacts, or report hashes.
    """

    workflow_status: str | None = Field(None, description="new, triage, investigating, contained, resolved, false_positive")
    assignee: str | None = Field(None, max_length=120)
    tags: list[str] | str | None = None
    notes: str | None = Field(None, max_length=8000)
    severity_override: str | None = Field(None, description="none, low, medium, high, critical")
    closure_summary: str | None = Field(None, max_length=4000)
    title: str | None = Field(None, max_length=180)


def _service() -> CaseHistoryService:
    return CaseHistoryService()


@router.get("/cases", response_class=JSONResponse)
async def list_cases(limit: int = Query(20, ge=1, le=100)):
    """최근 분석 케이스 목록을 반환합니다."""
    return {"success": True, "cases": _service().list_cases(limit=limit)}



@router.post("/cases/prune", response_class=JSONResponse)
async def prune_cases(
    request: Request,
    keep_last: int = Query(50, ge=0, le=1000),
    older_than_days: int | None = Query(None, ge=0, le=3650),
    dry_run: bool = Query(True),
    remove_files: bool = Query(True),
):
    """오래된 케이스를 정리합니다. 기본은 dry-run으로 후보만 반환합니다."""
    result = _service().prune_cases(
        keep_last=keep_last,
        older_than_days=older_than_days,
        dry_run=dry_run,
        remove_files=remove_files,
    )
    AuditLogService().record(
        "case.prune",
        request=request,
        status="success",
        details={
            "keep_last": keep_last,
            "older_than_days": older_than_days,
            "dry_run": dry_run,
            "candidate_count": result.get("candidate_count"),
            "removed_case_records": result.get("removed_case_records"),
            "removed_files": result.get("removed_files"),
        },
    )
    return {"success": True, **result}



@router.get("/cases/workflow/summary", response_class=JSONResponse)
async def workflow_summary():
    """케이스 워크플로 보드 요약을 반환합니다."""
    return {"success": True, "summary": _service().workflow_summary()}


@router.patch("/cases/{case_id}/workflow", response_class=JSONResponse)
async def update_case_workflow(case_id: str, payload: CaseWorkflowUpdate, request: Request):
    """케이스 담당자/상태/태그/분석 메모를 수정합니다."""
    actor = actor_from_request(request)
    try:
        updated = _service().update_case_workflow(
            case_id,
            workflow_status=payload.workflow_status,
            assignee=payload.assignee,
            tags=payload.tags,
            notes=payload.notes,
            severity_override=payload.severity_override,
            closure_summary=payload.closure_summary,
            title=payload.title,
            updated_by=actor.subject,
        )
    except KeyError:
        AuditLogService().record("case.workflow.update", request=request, status="failure", case_id=case_id, details={"reason": "not_found"})
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")
    except ValueError as exc:
        AuditLogService().record("case.workflow.update", request=request, status="failure", case_id=case_id, details={"reason": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))

    AuditLogService().record(
        "case.workflow.update",
        request=request,
        status="success",
        case_id=case_id,
        details={
            "workflow_status": updated.get("workflow_status"),
            "assignee": updated.get("assignee"),
            "tags": updated.get("tags"),
            "severity_override": updated.get("severity_override"),
        },
    )
    return {"success": True, "case": updated}

@router.get("/cases/{case_id}", response_class=JSONResponse)
async def get_case(case_id: str, request: Request):
    """단일 케이스 메타데이터와 대시보드 미리보기를 반환합니다."""
    try:
        case = _service().get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    preview = None
    if case.get("exists"):
        try:
            preview = load_preview(case["work_dir"])
        except FileNotFoundError:
            preview = None
    AuditLogService().record("case.view", request=request, status="success", case_id=case_id, details={"exists": case.get("exists")})
    return {"success": True, "case": case, "preview": preview}


@router.get("/cases/{case_id}/report")
async def get_case_report(
    case_id: str,
    request: Request,
    file_type: str = Query("html", pattern="^(html|json|csv|iocs|rules|pdf|manifest|zip)$"),
):
    """케이스 ID 기준으로 산출물을 다운로드합니다. 파일 시스템 경로를 URL에 노출하지 않습니다."""
    try:
        case = _service().get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    from api.services.path_boundary import WorkDirBoundaryError, validate_managed_work_dir
    try:
        work_path = validate_managed_work_dir(
            str(case.get("work_dir") or ""), allow_temp=True, must_exist=True
        )
    except (WorkDirBoundaryError, FileNotFoundError):
        raise HTTPException(status_code=404, detail="케이스 작업 디렉토리를 찾을 수 없습니다.")

    # BREACHSCOPE_P0_11_CASE_REPORT_BOUNDARY_V1
    report_prefix = work_path / "out" / "report"
    suffix_map = {
        "html": ".html",
        "json": ".json",
        "csv": ".csv",
        "iocs": ".iocs.csv",
        "rules": ".rules.csv",
        "pdf": ".pdf",
        "manifest": ".manifest.json",
        "zip": ".zip",
    }
    media_map = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "iocs": "text/csv",
        "rules": "text/csv",
        "pdf": "application/pdf",
        "manifest": "application/json",
        "zip": "application/zip",
    }
    file_path = report_prefix.with_suffix(suffix_map[file_type])
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"{file_type.upper()} 산출물을 찾을 수 없습니다.")
    AuditLogService().record("case.download", request=request, status="success", case_id=case_id, target=file_path.name, details={"file_type": file_type})
    return FileResponse(path=str(file_path), filename=file_path.name, media_type=media_map[file_type])


@router.delete("/cases/{case_id}", response_class=JSONResponse)
async def delete_case(case_id: str, request: Request, remove_files: bool = Query(True)):
    """케이스 이력에서 제거합니다. 안전한 작업 디렉토리만 파일까지 삭제합니다."""
    try:
        result = _service().delete_case(case_id, remove_files=remove_files)
    except KeyError:
        AuditLogService().record("case.delete", request=request, status="failure", case_id=case_id, details={"reason": "not_found"})
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")
    AuditLogService().record("case.delete", request=request, status="success", case_id=case_id, details=result)
    return {"success": True, **result}
