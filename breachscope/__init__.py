"""
BreachScope: 자동화된 디지털 포렌식 분석 도구

주요 기능:
- 규칙 기반 탐지
- 시간 기반 상관분석
- 시나리오 추론
- 리포트 생성
"""

__version__ = "1.0.0"
__author__ = "BreachScope Team"
__description__ = "자동화된 디지털 포렌식 및 사고 대응 로그 분석 도구"

__all__ = [
    "collector",
    "normalizer",
    "decoder",
    "analyzer",
    "correlator",
    "scenario",
    "storage",
    "utils",
    "rules",
    "config",
    "exceptions",
    "reporting",
    "pipeline",
]

# 공통 유틸리티 import
from .common import setup_logging, setup_path

# 프로젝트 경로 설정
setup_path()

# 로깅 설정
setup_logging()
