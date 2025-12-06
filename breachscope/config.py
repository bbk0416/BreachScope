"""
설정 관리 모듈
환경 변수, 설정 파일, 기본값을 통합 관리합니다.
"""
import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class Config:
    """BreachScope 설정"""

    # 리포트 설정
    redact: bool = True  # 민감 정보 마스킹
    default_severity: str = "medium"  # 기본 심각도

    # 상관분석 설정
    time_window_default: int = 300  # 기본 시간 윈도우 (초)

    # 필터 설정
    min_severity: Optional[str] = None
    mitre_include: Optional[List[str]] = None
    mitre_exclude: Optional[List[str]] = None
    host_include: Optional[List[str]] = None

    # 출력 설정
    export_json: bool = False
    export_csv: bool = False
    render_pdf: bool = False

    # 기타 설정
    log_level: str = "INFO"
    max_events: Optional[int] = None  # 최대 이벤트 수 (None이면 제한 없음)

    @classmethod
    def from_env(cls) -> 'Config':
        """
        환경 변수에서 설정 로드

        환경 변수:
            BS_REDACT: "0"이면 마스킹 비활성화
            BS_LOG_LEVEL: 로그 레벨 (DEBUG, INFO, WARNING, ERROR)
            BS_MAX_EVENTS: 최대 이벤트 수
        """
        redact = os.getenv("BS_REDACT", "1") != "0"
        log_level = os.getenv("BS_LOG_LEVEL", "INFO").upper()
        max_events_str = os.getenv("BS_MAX_EVENTS")
        max_events = int(max_events_str) if max_events_str else None

        return cls(
            redact=redact,
            log_level=log_level,
            max_events=max_events,
        )

    @classmethod
    def from_file(cls, path: Path) -> 'Config':
        """
        YAML 파일에서 설정 로드

        Args:
            path: 설정 파일 경로

        Returns:
            Config 객체
        """
        if not path.exists():
            return cls.from_env()

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return cls.from_env()

            return cls(
                redact=data.get("redact", True),
                default_severity=data.get("default_severity", "medium"),
                time_window_default=data.get("time_window_default", 300),
                min_severity=data.get("min_severity"),
                mitre_include=data.get("mitre_include"),
                mitre_exclude=data.get("mitre_exclude"),
                host_include=data.get("host_include"),
                export_json=data.get("export_json", False),
                export_csv=data.get("export_csv", False),
                render_pdf=data.get("render_pdf", False),
                log_level=data.get("log_level", "INFO"),
                max_events=data.get("max_events"),
            )
        except Exception:
            return cls.from_env()

    @classmethod
    def default(cls) -> 'Config':
        """기본 설정 반환"""
        return cls.from_env()

    def to_dict(self) -> Dict[str, Any]:
        """설정을 딕셔너리로 변환"""
        return {
            "redact": self.redact,
            "default_severity": self.default_severity,
            "time_window_default": self.time_window_default,
            "min_severity": self.min_severity,
            "mitre_include": self.mitre_include,
            "mitre_exclude": self.mitre_exclude,
            "host_include": self.host_include,
            "export_json": self.export_json,
            "export_csv": self.export_csv,
            "render_pdf": self.render_pdf,
            "log_level": self.log_level,
            "max_events": self.max_events,
        }

    def merge(self, other: 'Config') -> 'Config':
        """
        다른 설정과 병합 (other의 값이 우선)

        Args:
            other: 병합할 Config 객체

        Returns:
            병합된 Config 객체
        """
        merged = Config()
        for key, value in self.to_dict().items():
            other_value = getattr(other, key)
            if other_value is not None:
                setattr(merged, key, other_value)
            else:
                setattr(merged, key, value)
        return merged
