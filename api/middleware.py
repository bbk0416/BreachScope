"""
FastAPI 미들웨어 설정
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from api.security import ApiKeyAuthMiddleware

logger = logging.getLogger(__name__)

def setup_middleware(app: FastAPI):
    """미들웨어 설정"""
    # CORS 설정
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # 프로덕션에서는 특정 도메인으로 제한
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Optional product deployment guard. Disabled unless BS_API_KEY is set.
    app.add_middleware(ApiKeyAuthMiddleware)

    logger.info("미들웨어 설정 완료")
