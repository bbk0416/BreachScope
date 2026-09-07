"""
BreachScope: 자동화된 디지털 포렌식 분석 도구

주요 기능:
- 규칙 기반 탐지
- 시간 기반 상관분석
- 시나리오 추론
- 리포트 생성
"""

__version__ = "1.0.0"
__author__ = "bbk0416"
__email__ = "bbk0416@gmail.com"
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

# BREACHSCOPE_P2_07J_SCENARIO_USER_SCOPE_V1
# Keep P0-05 host/session scoping intact while extending it with the user
# boundary required by P2-07I activity chains. The installer replaces only the
# private evidence-scope helpers used dynamically by scenario inference.
from . import scenario as _scenario
from .scenario_user_scope import install as _install_scenario_user_scope

_install_scenario_user_scope(_scenario)

# BREACHSCOPE_P2_07M_HOST_SCOPED_SESSION_CHAINS_V1
# Windows LogonId/SessionId values are host-local. Partition explicit session
# correlation by host while preserving P2-07I activity fallback semantics.
from . import correlator as _correlator
from .correlator_session_scope import install as _install_correlator_session_scope

_install_correlator_session_scope(_correlator)
