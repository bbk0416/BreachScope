"""
이벤트 정규화 모듈
이벤트 데이터를 표준 형식으로 정규화합니다.
"""
from typing import Iterable, Iterator
import logging
from .schemas import Event

logger = logging.getLogger(__name__)


def normalize(events: Iterable[Event]) -> Iterator[Event]:
    """
    이벤트를 정규화하여 반환

    Args:
        events: 정규화할 이벤트 이터러블

    Yields:
        Event: 정규화된 이벤트 객체

    Note:
        - 문자열 필드의 앞뒤 공백 제거
        - 호스트명 및 명령줄 정규화
    """
    for e in events:
        # Minimal normalization: trim strings
        e.host = e.host.strip() if e.host else ""
        if e.command_line:
            e.command_line = e.command_line.strip()
        yield e
