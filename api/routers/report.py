"""
리포트 API 라우터
"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
import logging

from api.services.report_preview import load_preview


logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/report-preview/{work_dir:path}", response_class=JSONResponse)
async def get_report_preview(work_dir: str):
    """웹 UI 대시보드용 리포트 미리보기 JSON을 반환합니다."""
    try:
        return load_preview(work_dir)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="미리보기용 report.json을 찾을 수 없습니다.")
    except Exception as e:
        # BREACHSCOPE_P2_06I_SANITIZED_INTERNAL_ERRORS_V1
        logger.error(f"리포트 미리보기 오류: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="리포트 미리보기 중 내부 오류가 발생했습니다.",
        ) from e


@router.get("/report/{work_dir:path}")
async def get_report(
    work_dir: str,
    file_type: str = Query("html", pattern="^(html|json|csv|iocs|rules|pdf|manifest|zip)$")
):
    """
    리포트 파일 다운로드

    Args:
        work_dir: 작업 디렉토리 경로
        file_type: 파일 타입 (html, json, csv, pdf)
    """
    try:
        from api.services.path_boundary import WorkDirBoundaryError, validate_managed_work_dir
        try:
            work_path = validate_managed_work_dir(
                work_dir, allow_temp=True, must_exist=True
            )
        except (WorkDirBoundaryError, FileNotFoundError):
            raise HTTPException(status_code=404, detail="작업 디렉토리를 찾을 수 없습니다.")

        # BREACHSCOPE_P0_11_REPORT_ROUTE_BOUNDARY_V1

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
        if file_path.exists():
            return FileResponse(
                path=str(file_path),
                filename=file_path.name,
                media_type=media_map.get(file_type, "application/octet-stream")
            )
        raise HTTPException(status_code=404, detail=f"{file_type.upper()} 리포트를 찾을 수 없습니다.")
    except HTTPException:
        raise
    except Exception as e:
        # BREACHSCOPE_P2_06I_SANITIZED_INTERNAL_ERRORS_V1
        logger.error(f"리포트 다운로드 오류: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="리포트 다운로드 중 내부 오류가 발생했습니다.",
        ) from e
