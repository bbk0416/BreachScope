"""
BreachScope FastAPI 메인 애플리케이션
"""
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import logging

from breachscope.common import setup_path
setup_path()

from breachscope.exceptions import BreachScopeError
from api.routers import analyze, report, rules, health, web
from api.middleware import setup_middleware

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI 앱 생성
app = FastAPI(
    title="BreachScope",
    description="디지털 포렌식 로그 분석 시스템",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# 미들웨어 설정
setup_middleware(app)

# 라우터 등록
app.include_router(web.router)  # 루트 경로 (웹 UI)
app.include_router(analyze.router, prefix="/api", tags=["analysis"])
app.include_router(report.router, prefix="/api", tags=["reports"])
app.include_router(rules.router, prefix="/api", tags=["rules"])
app.include_router(health.router, prefix="/api", tags=["health"])

# 루트 엔드포인트
@app.get("/", response_class=JSONResponse)
async def root():
    """루트 엔드포인트"""
    return {
        "name": "BreachScope",
        "version": "1.0.0",
        "description": "디지털 포렌식 로그 분석 시스템",
        "docs": "/api/docs"
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
