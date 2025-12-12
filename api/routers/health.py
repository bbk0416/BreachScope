"""
헬스 체크 API 라우터
"""
from fastapi import APIRouter
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health", response_class=JSONResponse)
async def health_check():
    """
    헬스 체크 엔드포인트
    """
    return {
        "status": "healthy",
        "service": "BreachScope",
        "version": "1.0.0"
    }
