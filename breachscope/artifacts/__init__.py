"""
다계층 아티팩트 수집 모듈
Prefetch, Registry, USB 기록, 브라우저 이력 등을 수집합니다.
"""
from .collector import ArtifactCollector
from .prefetch import collect_prefetch
from .registry import collect_registry
from .usb import collect_usb_history
from .browser import collect_browser_history
from .classifier import (
    ArtifactCategory,
    ArtifactClassifier,
    classify_and_organize,
)

__all__ = [
    "ArtifactCollector",
    "collect_prefetch",
    "collect_registry",
    "collect_usb_history",
    "collect_browser_history",
    "ArtifactCategory",
    "ArtifactClassifier",
    "classify_and_organize",
]
