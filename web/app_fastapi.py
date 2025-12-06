"""
BreachScope FastAPI 웹 애플리케이션
Streamlit 대신 FastAPI + Jinja2 템플릿 기반 웹 UI
"""
import os
import sys
import tempfile
import time
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
import logging

# 프로젝트 루트를 Python 경로에 추가
from breachscope.common import setup_path
setup_path()

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from jinja2 import Environment, FileSystemLoader
import uvicorn

from breachscope.pipeline import Pipeline
from breachscope.ingest import convert_evtx_dir, collect_windows_logs
from breachscope.exceptions import BreachScopeError

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="BreachScope",
    description="디지털 포렌식 로그 분석 시스템",
    version="1.0.0"
)

# 템플릿 디렉토리 설정
templates_dir = Path(__file__).parent.parent / "templates"
jinja_env = Environment(loader=FileSystemLoader(str(templates_dir)))

def render_template(template_name: str, **kwargs) -> str:
    """템플릿 렌더링"""
    template = jinja_env.get_template(template_name)
    return template.render(**kwargs)


# 전역 예외 핸들러
@app.exception_handler(BreachScopeError)
async def breachscope_exception_handler(request: Request, exc: BreachScopeError):
    """BreachScope 커스텀 예외 핸들러"""
    logger.error(f"BreachScope 오류: {exc.message}", exc_info=True, extra=exc.details)
    return JSONResponse(
        status_code=500,
        content={
            "error": "분석 오류",
            "message": exc.message,
            "details": exc.details
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """요청 검증 오류 핸들러"""
    logger.warning(f"요청 검증 실패: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={
            "error": "요청 검증 실패",
            "message": "입력 데이터가 올바르지 않습니다.",
            "details": exc.errors()
        }
    )


@app.get("/", response_class=HTMLResponse)
async def index():
    """메인 페이지"""
    html = render_template("web_index.html")
    return HTMLResponse(content=html)


def _create_work_directory(work_dir: Optional[str] = None) -> Path:
    """
    작업 디렉토리 생성

    Args:
        work_dir: 사용자 지정 디렉토리 경로 (선택)

    Returns:
        작업 디렉토리 Path

    Raises:
        HTTPException: 디렉토리 생성 실패 시
    """
    current_timestamp = int(time.time())
    current_pid = os.getpid()

    # 사용자가 지정한 작업 디렉토리가 있으면 우선 사용
    if work_dir and work_dir.strip():
        try:
            user_work_dir = Path(work_dir.strip())
            if not user_work_dir.is_absolute():
                user_work_dir = Path.cwd() / user_work_dir

            if not user_work_dir.exists():
                user_work_dir.mkdir(parents=True, exist_ok=True)

            if user_work_dir.exists() and user_work_dir.is_dir():
                # 쓰기 권한 확인
                try:
                    test_file = user_work_dir / ".test_write"
                    test_file.write_text("test")
                    test_file.unlink()
                    logger.info(f"사용자 지정 작업 디렉토리 사용: {user_work_dir}")
                    return user_work_dir
                except (PermissionError, OSError) as perm_err:
                    logger.warning(f"사용자 지정 디렉토리 권한 오류: {perm_err}, 시스템 임시 디렉토리 사용...")
        except Exception as e:
            logger.warning(f"사용자 지정 작업 디렉토리 오류: {e}, 시스템 임시 디렉토리 사용...")

    # 시스템 임시 디렉토리 사용 (권한 문제 최소화)
    try:
        work = Path(tempfile.mkdtemp(prefix="bs_web_"))
        logger.info(f"시스템 임시 작업 디렉토리 생성: {work}")
        return work
    except Exception as e:
        logger.error(f"시스템 임시 디렉토리 생성 실패: {e}")
        raise HTTPException(
            status_code=500,
            detail="작업 디렉토리 생성 실패. 디스크 공간을 확인하거나 관리자에게 문의하세요."
        )


@app.post("/api/analyze")
async def analyze(
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
    work = None
    try:
        # Redaction 설정
        os.environ["BS_REDACT"] = "1" if redact else "0"

        # 작업 디렉토리 생성
        work = _create_work_directory(work_dir)

        # 입력 디렉토리 설정
        if work_dir and work_dir.strip():
            in_dir = work
        else:
            in_dir = work / "input"
            in_dir.mkdir(parents=True, exist_ok=True)

        # Windows 이벤트 로그 자동 수집
        if collect_evtx:
            log_names = None
            if collect_logs:
                log_names = [x.strip() for x in collect_logs.split(",") if x.strip()]

            try:
                collected_dir = collect_windows_logs(
                    output_dir=None,
                    log_names=log_names,
                    hours=collect_hours,
                )
                if collected_dir:
                    in_dir = collected_dir
                    do_evtx = True
                    logger.info(f"Windows 이벤트 로그 수집 완료: {collected_dir}")
                else:
                    raise HTTPException(
                        status_code=500,
                        detail="Windows 이벤트 로그 수집 실패. 관리자 권한으로 실행하거나 특정 로그에 대한 접근 권한을 확인하세요."
                    )
            except PermissionError as e:
                logger.error(f"이벤트 로그 수집 권한 오류: {e}")
                raise HTTPException(
                    status_code=403,
                    detail=f"이벤트 로그 수집 권한 부족: {e}. 관리자 권한으로 실행하거나 접근 가능한 로그만 선택하세요."
                )
            except Exception as e:
                logger.error(f"이벤트 로그 수집 오류: {e}")
                raise HTTPException(
                    status_code=500,
                    detail=f"이벤트 로그 수집 중 오류 발생: {e}"
                )

        # 파일 저장 (파일이 업로드된 경우)
        saved_paths = []
        if files and len(files) > 0:
            upload_dir = in_dir
            for file in files:
                if not file.filename:
                    continue

                file_path = upload_dir / file.filename
                try:
                    with file_path.open("wb") as f:
                        content = await file.read()
                        f.write(content)
                    saved_paths.append(file_path)
                    logger.info(f"파일 저장 완료: {file_path}")
                except (PermissionError, OSError) as e:
                    logger.error(f"파일 저장 실패: {file_path} - {e}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"파일 저장 실패: {e}. 디렉토리 쓰기 권한을 확인하거나 다른 경로를 지정하세요."
                    )

        # 규칙 디렉토리 설정
        if use_repo_rules:
            rules_dir = Path("rules").resolve()
        else:
            rules_dir = work / "rules"
            rules_dir.mkdir(parents=True, exist_ok=True)

        # EVTX 변환
        if do_evtx:
            if collect_evtx:
                converted = convert_evtx_dir(in_dir)
                if converted:
                    in_dir = converted

            if saved_paths and any(p.suffix.lower() == ".evtx" for p in saved_paths):
                upload_dir = saved_paths[0].parent
                converted = convert_evtx_dir(upload_dir)
                if converted and not collect_evtx:
                    in_dir = converted

        # 파이프라인 실행
        def split_csv(s: str) -> Optional[List[str]]:
            return [x.strip() for x in s.split(",") if x.strip()] if s else None

        # Config에서 max_events 가져오기 (대용량 파일 처리 제한)
        from breachscope.config import Config
        config = Config.from_env()
        max_events = config.max_events

        pipeline = Pipeline(
            rules_dir=rules_dir,
            min_severity=min_severity,
            mitre_include=split_csv(mitre_include),
            mitre_exclude=split_csv(mitre_exclude),
            host_include=split_csv(host_include),
            max_events=max_events,
        )

        out_prefix = work / "out" / "report"
        out_prefix.parent.mkdir(parents=True, exist_ok=True)

        html_path, count = pipeline.run(
            input_dir=in_dir,
            out_prefix=out_prefix,
            export_json=True,
            export_csv=True,
            render_pdf=render_pdf,
        )

        # 리포트 파일 경로
        json_path = out_prefix.with_suffix(".json")
        csv_path = out_prefix.with_suffix(".csv")
        pdf_path = out_prefix.with_suffix(".pdf") if render_pdf else None

        return {
            "success": True,
            "count": count,
            "html_path": str(html_path),
            "json_path": str(json_path) if json_path.exists() else None,
            "csv_path": str(csv_path) if csv_path.exists() else None,
            "pdf_path": str(pdf_path) if pdf_path and pdf_path.exists() else None,
            "work_dir": str(work),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"분석 중 오류 발생: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"분석 실패: {str(e)}"
        )


@app.get("/api/report/{work_dir:path}")
async def get_report(work_dir: str, file_type: str = "html"):
    """
    리포트 파일 다운로드

    Args:
        work_dir: 작업 디렉토리 경로
        file_type: 파일 타입 (html, json, csv, pdf)
    """
    work_path = Path(work_dir)
    if not work_path.exists():
        raise HTTPException(status_code=404, detail="리포트를 찾을 수 없습니다")

    file_map = {
        "html": "out/report.html",
        "json": "out/report.json",
        "csv": "out/report.csv",
        "pdf": "out/report.pdf",
    }

    file_path = work_path / file_map.get(file_type, "out/report.html")
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="파일을 찾을 수 없습니다")

    media_type_map = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
    }

    return FileResponse(
        file_path,
        media_type=media_type_map.get(file_type, "text/html"),
        filename=f"report.{file_type}",
    )


@app.get("/api/rules")
async def get_rules():
    """규칙 목록 조회"""
    from breachscope.rules import load_rules

    try:
        rules_dir = Path("rules")
        rules = load_rules(rules_dir)
        return {
            "count": len(rules),
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "description": r.description,
                    "severity": r.severity,
                    "mitre_technique": r.mitre_technique,
                }
                for r in rules
            ],
        }
    except Exception as e:
        logger.error(f"규칙 로드 실패: {e}")
        raise HTTPException(status_code=500, detail=f"규칙 로드 실패: {str(e)}")


@app.get("/api/health")
async def health_check():
    """헬스 체크 엔드포인트"""
    return {
        "status": "healthy",
        "version": "1.0.0"
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8501)
