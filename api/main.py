"""
BreachScope FastAPI 메인 애플리케이션
"""
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import logging
import os

from breachscope.common import setup_path
setup_path()

from breachscope.exceptions import BreachScopeError
from api.routers import analyze, report, rules, health, web, cases, auth, audit, backups, ops
from api.middleware import setup_middleware
from breachscope.release import runtime_build_info

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

docs_enabled = os.getenv("BS_DISABLE_DOCS", "").strip().lower() not in {"1", "true", "yes"}

# FastAPI 앱 생성
app = FastAPI(
    title="BreachScope",
    description="디지털 포렌식 로그 분석 시스템",
    version="1.0.0",
    docs_url="/api/docs" if docs_enabled else None,
    redoc_url="/api/redoc" if docs_enabled else None,
)

# 미들웨어 설정
setup_middleware(app)

# 라우터 등록
app.include_router(web.router)  # 루트 경로 (웹 UI)
app.include_router(auth.router, prefix="/api", tags=["auth"])
app.include_router(analyze.router, prefix="/api", tags=["analysis"])
app.include_router(report.router, prefix="/api", tags=["reports"])
app.include_router(cases.router, prefix="/api", tags=["cases"])
app.include_router(audit.router, prefix="/api", tags=["audit"])
app.include_router(backups.router, prefix="/api", tags=["backups"])
app.include_router(ops.router, prefix="/api", tags=["operations"])
app.include_router(rules.router, prefix="/api", tags=["rules"])
app.include_router(health.router, prefix="/api", tags=["health"])

# API 정보 엔드포인트
@app.get("/api/info", response_class=JSONResponse)
async def api_info():
    """API 정보 엔드포인트"""
    return {
        "name": "BreachScope",
        "version": "1.0.0",
        "description": "디지털 포렌식 로그 분석 시스템",
        "docs": "/api/docs" if docs_enabled else None,
        "auth_enabled": bool(os.getenv("BS_API_KEY", "").strip() or os.getenv("BS_ADMIN_PASSWORD", "").strip()),
        "api_key_enabled": bool(os.getenv("BS_API_KEY", "").strip()),
        "password_login_enabled": bool(os.getenv("BS_ADMIN_PASSWORD", "").strip()),
        "case_history_path": os.getenv("BS_CASE_HISTORY_PATH", "~/.breachscope/case_history.json"),
        "cases_root": os.getenv("BS_CASES_ROOT", "~/.breachscope/cases"),
        "audit_log_path": os.getenv("BS_AUDIT_LOG_PATH", "~/.breachscope/audit.jsonl"),
        "audit_enabled": os.getenv("BS_AUDIT_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"},
        "auth_lockout": {
            "max_failures": int(os.getenv("BS_AUTH_MAX_FAILURES", "5") or "5"),
            "lockout_seconds": int(os.getenv("BS_AUTH_LOCKOUT_SECONDS", "300") or "300"),
        },
        "backup_root": os.getenv("BS_BACKUP_ROOT", "~/.breachscope/backups"),
        "metrics_endpoint": "/api/metrics",
        "config_check_endpoint": "/api/ops/config-check",
        "self_test_endpoint": "/api/ops/self-test",
        "release_info_endpoint": "/api/ops/release-info",
        "go_live_endpoint": "/api/ops/go-live",
        "release": runtime_build_info(),
    }

# 전역 예외 핸들러
@app.exception_handler(BreachScopeError)
async def breachscope_exception_handler(request, exc: BreachScopeError):
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
async def validation_exception_handler(request, exc: RequestValidationError):
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
