"""
분석 API 라우터
"""
from fastapi import APIRouter, File, UploadFile, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import List, Optional
import logging
from api.services.upload_policy import UploadLimitError

from api.services.analysis_service import AnalysisService
from api.services.audit_log import AuditLogService

logger = logging.getLogger(__name__)

router = APIRouter()

# 서비스 인스턴스
analysis_service = AnalysisService()


@router.post("/analyze", response_class=JSONResponse)
async def analyze(
    request: Request,
    files: List[UploadFile] = File(None),
    use_repo_rules: bool = Form(True),
    min_severity: Optional[str] = Form("medium"),
    mitre_include: Optional[str] = Form(""),
    mitre_exclude: Optional[str] = Form(""),
    host_include: Optional[str] = Form(""),
    redact: bool = Form(True),
    render_pdf: bool = Form(False),
    do_evtx: bool = Form(False),
    collect_evtx: bool = Form(False),
    collect_logs: Optional[str] = Form(""),
    collect_hours: Optional[int] = Form(None),
    work_dir: Optional[str] = Form(""),
):
    """
    로그 분석 API

    Returns:
        분석 결과 및 리포트 다운로드 링크
    """
    try:
        result = await analysis_service.analyze(
            files=files,
            use_repo_rules=use_repo_rules,
            min_severity=min_severity,
            mitre_include=mitre_include,
            mitre_exclude=mitre_exclude,
            host_include=host_include,
            redact=redact,
            render_pdf=render_pdf,
            do_evtx=do_evtx,
            collect_evtx=collect_evtx,
            collect_logs=collect_logs,
            collect_hours=collect_hours,
            work_dir=work_dir,
        )
        AuditLogService().record(
            "analysis.run",
            request=request,
            status="success",
            case_id=result.get("case_id"),
            target=str(result.get("work_dir") or ""),
            details={
                "finding_count": result.get("count"),
                "risk_score": result.get("risk_score"),
                "risk_level": result.get("risk_level"),
                "uploaded_files": len([f for f in (files or []) if getattr(f, "filename", "")]),
                "render_pdf": render_pdf,
                "collect_evtx": collect_evtx,
            },
        )
        return result
    except UploadLimitError as exc:
        # BREACHSCOPE_P1_01_UPLOAD_413_V1
        raise HTTPException(
            status_code=413,
            detail={
                "code": "UPLOAD_LIMIT_EXCEEDED",
                "message": str(exc),
            },
        ) from exc
    except PermissionError as e:
        # BREACHSCOPE_P2_06O_SANITIZED_PERMISSION_ERRORS_V1
        AuditLogService().record("analysis.run", request=request, status="failure", details={"error": str(e), "type": "PermissionError"})
        logger.error(f"권한 오류: {e}")
        raise HTTPException(
            status_code=403,
            detail="권한이 부족합니다. 관리자 권한으로 실행하거나 접근 가능한 로그만 선택하세요."
        ) from e
    except Exception as e:
        # BREACHSCOPE_P2_06I_SANITIZED_INTERNAL_ERRORS_V1
        AuditLogService().record("analysis.run", request=request, status="failure", details={"error": str(e), "type": type(e).__name__})
        logger.error(f"분석 오류: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="분석 중 내부 오류가 발생했습니다."
        ) from e
