"""
FastAPI 미들웨어 설정
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import os

from api.security import ApiKeyAuthMiddleware
from api.services.upload_policy import UploadRequestLimitMiddleware

logger = logging.getLogger(__name__)

# BREACHSCOPE_P2_06F_CORS_ORIGIN_ALLOWLIST_V2
def allowed_cors_origins() -> list[str]:
    """Return exact credentialed CORS origins configured for this deployment."""
    raw = os.getenv("BS_ALLOWED_ORIGINS", "").strip()
    if not raw:
        return []

    origins: list[str] = []
    for value in raw.split(","):
        origin = value.strip().rstrip("/")
        if not origin:
            continue
        if origin == "*":
            raise ValueError(
                "BS_ALLOWED_ORIGINS must not contain '*' when credentials are enabled"
            )
        if origin not in origins:
            origins.append(origin)
    return origins


def setup_middleware(app: FastAPI):
    """미들웨어 설정"""
    # CORS 설정
    cors_origins = allowed_cors_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Optional product deployment guard. Disabled unless BS_API_KEY is set.
    app.add_middleware(ApiKeyAuthMiddleware)

    # BREACHSCOPE_P1_01_REQUEST_LIMIT_V1
    app.add_middleware(UploadRequestLimitMiddleware)

    logger.info("미들웨어 설정 완료")
