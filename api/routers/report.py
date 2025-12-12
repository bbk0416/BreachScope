"""
리포트 API 라우터
"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pathlib import Path
import logging


logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/report/{work_dir:path}")
async def get_report(
    work_dir: str,
    file_type: str = Query("html", regex="^(html|json|csv|pdf)$")
):
    """
    리포트 파일 다운로드

    Args:
        work_dir: 작업 디렉토리 경로
        file_type: 파일 타입 (html, json, csv, pdf)
    """
    try:
        work_path = Path(work_dir)
        if not work_path.exists():
            raise HTTPException(status_code=404, detail="작업 디렉토리를 찾을 수 없습니다.")

        report_prefix = work_path / "out" / "report"

        if file_type == "html":
            html_path = report_prefix.with_suffix(".html")
            if html_path.exists():
                # HTML 리포트 파일 반환
                return FileResponse(
                    path=str(html_path),
                    filename=html_path.name,
                    media_type="text/html"
                )
            else:
                raise HTTPException(status_code=404, detail="HTML 리포트를 찾을 수 없습니다.")
        else:
            file_path = report_prefix.with_suffix(f".{file_type}")
            if file_path.exists():
                return FileResponse(
                    path=str(file_path),
                    filename=file_path.name,
                    media_type={
                        "json": "application/json",
                        "csv": "text/csv",
                        "pdf": "application/pdf"
                    }.get(file_type, "application/octet-stream")
                )
            else:
                raise HTTPException(status_code=404, detail=f"{file_type.upper()} 리포트를 찾을 수 없습니다.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"리포트 다운로드 오류: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"리포트 다운로드 중 오류 발생: {str(e)}")
