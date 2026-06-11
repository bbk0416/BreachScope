"""
BreachScope 커스텀 예외 클래스
"""
from typing import Optional


class BreachScopeError(Exception):
    """BreachScope 기본 예외"""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class RuleLoadError(BreachScopeError):
    """규칙 로딩 실패"""
    pass


class RuleValidationError(BreachScopeError):
    """규칙 검증 실패"""
    pass


class EventParseError(BreachScopeError):
    """이벤트 파싱 실패"""
    pass


class EventCollectionError(BreachScopeError):
    """이벤트 수집 실패"""
    pass


class CorrelationError(BreachScopeError):
    """상관분석 실패"""
    pass


class ScenarioInferenceError(BreachScopeError):
    """시나리오 추론 실패"""
    pass


class ReportGenerationError(BreachScopeError):
    """리포트 생성 실패"""
    pass


class StorageError(BreachScopeError):
    """저장소 오류"""
    pass


class ConfigurationError(BreachScopeError):
    """설정 오류"""
    pass
