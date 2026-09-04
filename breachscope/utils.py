"""
공통 유틸리티 함수
타임스탬프 파싱, 이벤트 키 생성 등 공통 기능 제공
"""
import logging
from typing import Any, Iterator, Optional, Tuple
from datetime import datetime, timezone

from .schemas import Event, Finding

logger = logging.getLogger(__name__)


def parse_timestamp(ts: str) -> Optional[datetime]:
    """
    타임스탬프 문자열을 datetime으로 변환 (통합 버전)

    Args:
        ts: 타임스탬프 문자열 (ISO 8601 형식)

    Returns:
        datetime 객체 또는 None (파싱 실패 시)
    """
    if not ts:
        return None

    t = ts.strip()
    if not t:
        return None

    try:
        # Z 접미사 처리 (UTC)
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"

        # ISO 8601 파싱
        dt = datetime.fromisoformat(t)

        # 타임존이 없으면 UTC로 가정
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt
    except (ValueError, TypeError) as e:
        logger.debug(f"타임스탬프 파싱 실패: {ts} - {e}")
        return None
    except Exception as e:
        logger.warning(f"타임스탬프 파싱 중 예상치 못한 오류: {ts} - {e}")
        return None


def get_event_key(event: Event) -> str:
    """
    이벤트의 고유 키 생성

    Args:
        event: Event 객체

    Returns:
        고유 키 문자열 (timestamp|host|source|event_id)
    """
    return f"{event.timestamp}|{event.host}|{event.source}|{event.event_id or ''}"


def _iter_event_raw_dicts(value: Any) -> Iterator[dict]:
    """Yield nested raw mappings once, including wrapped EVTX payloads."""
    stack = [value]
    seen = set()
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        yield current
        stack.extend(v for v in current.values() if isinstance(v, dict))


def get_windows_event_record_identity(event: Event) -> Tuple[str, str]:
    """Return (Channel, EventRecordID) when a Windows event exposes both."""
    raw = getattr(event, "raw", {}) or {}
    for mapping in _iter_event_raw_dicts(raw):
        lower = {str(k).casefold(): v for k, v in mapping.items()}
        system = lower.get("system")
        candidates = [system] if isinstance(system, dict) else []
        candidates.append(mapping)
        for candidate in candidates:
            lowered = {str(k).casefold(): v for k, v in candidate.items()}
            channel = str(lowered.get("channel") or "").strip()
            record_id = str(
                lowered.get("eventrecordid")
                or lowered.get("event_record_id")
                or lowered.get("record_id")
                or ""
            ).strip()
            if channel and record_id:
                return channel, record_id
    return "", ""


def get_event_identity_key(event: Event) -> str:
    """
    Return a correlation-safe event identity.

    Generic events retain the historical timestamp/host/source/event_id key.
    Real Windows EVTX records additionally use Channel + EventRecordID so two
    distinct records with identical coarse metadata cannot collapse together.
    """
    base_key = get_event_key(event)
    channel, record_id = get_windows_event_record_identity(event)
    if not channel or not record_id:
        return base_key
    return f"{base_key}|channel={channel}|event_record_id={record_id}"


def find_event_index(target_event: Event, events: list[Event]) -> Optional[int]:
    """
    이벤트 리스트에서 특정 이벤트의 인덱스 찾기 (고유 키 기반)

    Args:
        target_event: 찾을 이벤트
        events: 이벤트 리스트

    Returns:
        인덱스 또는 None (찾지 못한 경우)
    """
    target_key = get_event_key(target_event)
    for idx, event in enumerate(events):
        if get_event_key(event) == target_key:
            return idx
    return None


def match_finding_to_event(finding: Finding, event: Event) -> bool:
    """
    Finding이 특정 이벤트와 매칭되는지 확인 (고유 키 기반)

    Args:
        finding: Finding 객체
        event: Event 객체

    Returns:
        매칭 여부
    """
    return get_event_key(finding.event) == get_event_key(event)
