"""
이벤트 정규화 모듈
이벤트 데이터를 표준 형식으로 정규화합니다.
"""
from typing import Iterable, Iterator
import logging
from .schemas import Event
from .utils import get_event_identity_key, get_windows_event_record_identity

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
        - Channel + EventRecordID가 있는 Windows EVTX 중복 레코드는 한 번만 반환
        - strong identity가 없는 generic 이벤트는 기존처럼 모두 보존
    """
    seen_windows_events = set()

    for e in events:
        # Minimal normalization: trim strings
        e.host = e.host.strip() if e.host else ""
        if e.command_line:
            e.command_line = e.command_line.strip()

        # P2-08A: overlapping EVTX exports can contain the same Windows record
        # more than once. Only suppress duplicates when the event exposes the
        # strong Windows record identity; generic JSONL rows keep legacy
        # multiplicity because their coarse timestamp/host/source/event_id key
        # is not strong enough to prove that two rows are the same observation.
        channel, record_id = get_windows_event_record_identity(e)
        if channel and record_id:
            identity = get_event_identity_key(e)
            if identity in seen_windows_events:
                logger.debug("중복 Windows 이벤트 제거: %s", identity)
                continue
            seen_windows_events.add(identity)

        yield e


# BREACHSCOPE_P2_08A_WINDOWS_EVENT_DEDUP_V1
