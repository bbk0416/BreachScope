"""
로깅 설정 유틸리티
일관된 로깅 설정 제공
"""
import logging
import os
from typing import Optional


def setup_logging(
    level: Optional[str] = None,
    format_string: Optional[str] = None
) -> None:
    """
    로깅 설정

    Args:
        level: 로그 레벨 (DEBUG, INFO, WARNING, ERROR)
              None이면 환경 변수 BS_LOG_LEVEL 또는 기본값 INFO 사용
        format_string: 로그 포맷 문자열
                      None이면 기본 포맷 사용
    """
    if level is None:
        level = os.getenv("BS_LOG_LEVEL", "INFO").upper()

    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format=format_string
    )
