"""
헬스 체크 API 라우터
"""
from fastapi import APIRouter
from fastapi.responses import JSONResponse
import logging

from api.services.ops_status import live_status, readiness_status

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health", response_class=JSONResponse)
async def health_check():
    """
    헬스 체크 엔드포인트
    """
    live = live_status()
    return {
        "status": "healthy",
        "service": live["service"],
        "version": live["version"],
        "uptime_seconds": live["uptime_seconds"],
    }


@router.get("/health/live", response_class=JSONResponse)
async def liveness_check():
    """Kubernetes/Docker liveness probe."""
    return live_status()


@router.get("/health/ready", response_class=JSONResponse)
async def readiness_check():
    """Readiness probe that verifies writable storage and rule/template availability."""
    return readiness_status()
