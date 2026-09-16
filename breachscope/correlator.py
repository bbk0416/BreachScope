"""
시간 기반 상관분석 엔진
이벤트 간 시간적 연관성과 인과관계를 분석하여 이벤트 체인을 생성합니다.
"""
import logging
import hashlib
import bisect
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict

from .schemas import Event, Finding
from .utils import parse_timestamp, get_event_identity_key

logger = logging.getLogger(__name__)


@dataclass
class EventChain:
    """연관된 이벤트들의 체인"""
    chain_id: str
    events: List[Event]
    findings: List[Finding]  # 체인과 연관된 탐지 결과
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    description: str = ""
    confidence: float = 0.0  # 0.0 ~ 1.0
    chain_type: str = ""  # "download_exec", "session", "lateral_movement" 등


@dataclass
class CorrelationRule:
    """상관분석 규칙"""
    rule_id: str
    name: str
    description: str
    # 이벤트 A 발생 후 time_window 내에 이벤트 B가 발생하면 연관
    event_a_patterns: List[str]  # 이벤트 A를 식별하는 패턴 (source, event_id 등)
    event_b_patterns: List[str]  # 이벤트 B를 식별하는 패턴
    time_window_seconds: int = 300  # 기본 5분
    required_fields: List[str] = field(default_factory=list)  # 연관을 위한 공통 필드
    chain_type: str = "generic"


# 타임스탬프 파싱은 utils.parse_timestamp 사용
_parse_timestamp = parse_timestamp


# BREACHSCOPE_P0_07_CANONICAL_SOURCE_BRIDGE_V1
def _match_event_pattern(event: Event, patterns: List[str]) -> bool:
    """Match legacy event patterns, then fall back to canonical source tokens."""
    for pattern in patterns:
        if pattern.startswith("source:"):
            if event.source and pattern[7:].lower() in event.source.lower():
                return True
        elif pattern.startswith("event_id:"):
            if event.event_id and pattern[9:] == event.event_id:
                return True
        elif pattern.startswith("cmd:"):
            if event.command_line and pattern[4:].lower() in event.command_line.lower():
                return True
        elif event.source and pattern.lower() in event.source.lower():
            return True
    return _match_canonical_source(event, patterns)


# BREACHSCOPE_P0_03_REQUIRED_FIELDS_AND_V1
def _extract_common_key(
    event_a: Event,
    event_b: Event,
    fields: List[str],
) -> Optional[str]:
    """Return a common key only when every explicitly required field matches."""
    matched_parts: List[str] = []
    for field in fields:
        if field == "host":
            val_a, val_b = event_a.host, event_b.host
        elif field == "user":
            val_a, val_b = event_a.user, event_b.user
        elif field == "command_line":
            val_a, val_b = event_a.command_line, event_b.command_line
        else:
            val_a = event_a.raw.get(field)
            val_b = event_b.raw.get(field)

        if not (val_a and val_b and str(val_a).lower() == str(val_b).lower()):
            return None
        matched_parts.append(f"{field}:{val_a}")

    if not matched_parts:
        return None
    return " && ".join(matched_parts)

def correlate_events(
    events: List[Event],
    findings: List[Finding],
    correlation_rules: Optional[List[CorrelationRule]] = None,
) -> List[EventChain]:
    """
    이벤트들을 시간 기반으로 상관분석하여 체인을 생성합니다 (성능 최적화 버전).

    Args:
        events: 분석할 이벤트 목록
        findings: 탐지 결과 목록
        correlation_rules: 사용자 정의 상관 규칙 (None이면 기본 규칙 사용)

    Returns:
        생성된 이벤트 체인 목록
    """
    if not events:
        logger.debug("이벤트가 없어 상관분석을 건너뜁니다")
        return []

    logger.info(f"상관분석 시작: {len(events)}개 이벤트, {len(findings)}개 탐지")

    try:
        # 1. 타임스탬프 미리 파싱 및 인덱싱 (성능 최적화)
        indexed_events: List[Tuple[int, Event, datetime]] = []
        for i, event in enumerate(events):
            ts = _parse_timestamp(event.timestamp)
            if ts:
                indexed_events.append((i, event, ts))

        if not indexed_events:
            logger.warning("유효한 타임스탬프를 가진 이벤트가 없습니다")
            return []

        # 시간순 정렬 (한 번만)
        indexed_events.sort(key=lambda x: x[2])
        sorted_events = [event for _, event, _ in indexed_events]
        event_indices = {get_event_identity_key(event): idx for idx, (orig_idx, event, _) in enumerate(indexed_events)}

        # 타임스탬프 리스트 생성 (bisect를 위한)
        timestamps = [ts for _, _, ts in indexed_events]

        # 2. Finding을 이벤트 인덱스로 매핑 (고유 키 기반)
        finding_map: Dict[int, List[Finding]] = defaultdict(list)
        for finding in findings:
            event_idx = event_indices.get(get_event_identity_key(finding.event))
            if event_idx is None:
                # Identity-safe retry for generic or wrapped Windows events.
                finding_key = get_event_identity_key(finding.event)
                for idx, event in enumerate(sorted_events):
                    if finding_key == get_event_identity_key(event):
                        event_idx = idx
                        break
            if event_idx is not None:
                finding_map[event_idx].append(finding)

        # 기본 상관 규칙 정의
        if correlation_rules is None:
            correlation_rules = _get_default_correlation_rules()

        chains: List[EventChain] = []

        # 3. 각 상관 규칙에 대해 체인 생성.
        # B 패턴은 event/window마다 다시 평가하지 않고 규칙당 한 번만
        # 사전 계산합니다. 시간순 index와 B 후보 timestamp가 같은 순서를
        # 유지하므로 이후에는 bisect로 실제 B 후보만 조회할 수 있습니다.
        for rule in correlation_rules:
            logger.debug(f"규칙 적용 중: {rule.rule_id}")

            candidate_b_indices = [
                idx
                for idx, (_, event, _) in enumerate(indexed_events)
                if _match_event_pattern(event, rule.event_b_patterns)
            ]
            candidate_b_timestamps = [timestamps[idx] for idx in candidate_b_indices]

            for i, (orig_idx, event_a, ts_a) in enumerate(indexed_events):

                # 이벤트 A가 패턴과 매칭되는지 확인
                if not _match_event_pattern(event_a, rule.event_a_patterns):
                    continue

                # 시간 윈도우 계산
                window_end = ts_a + timedelta(seconds=rule.time_window_seconds)

                # i 이후이면서 window_end 이하인 B-pattern 후보만 조회합니다.
                candidate_start = bisect.bisect_right(candidate_b_indices, i)
                candidate_end = bisect.bisect_right(
                    candidate_b_timestamps,
                    window_end,
                    lo=candidate_start,
                )

                chain_events = [event_a]
                chain_findings: List[Finding] = []

                # 이벤트 A와 연관된 finding 추가
                if i in finding_map:
                    chain_findings.extend(finding_map[i])

                # 윈도우 내에서 B 패턴에 이미 매칭된 이벤트만 검색
                for candidate_pos in range(candidate_start, candidate_end):
                    j = candidate_b_indices[candidate_pos]
                    orig_idx_b, event_b, ts_b = indexed_events[j]

                    # 공통 필드 확인 (필요한 경우)
                    if rule.required_fields:
                        common_key = _extract_common_key(event_a, event_b, rule.required_fields)
                        if not common_key:
                            continue

                    chain_events.append(event_b)

                    # 이벤트 B와 연관된 finding 추가
                    if j in finding_map:
                        for finding in finding_map[j]:
                            if finding not in chain_findings:
                                chain_findings.append(finding)

                # 체인이 최소 2개 이상의 이벤트를 포함하는 경우만 추가
                if len(chain_events) >= 2:

                    # Confidence must use the actual last matched event, not
                    # the last candidate scanned inside the time window.
                    end_time = _parse_timestamp(chain_events[-1].timestamp)
                    time_span = end_time - ts_a if end_time else None

                    chain = EventChain(
                        chain_id=f"chain_{len(chains)+1}_{rule.chain_type}",
                        events=chain_events,
                        findings=chain_findings,
                        start_time=ts_a,
                        end_time=end_time,
                        description=rule.description,
                        confidence=_calculate_chain_confidence(chain_events, chain_findings, time_span),
                        chain_type=rule.chain_type,
                    )
                    chains.append(chain)

        # 세션 기반 상관 (로그온 세션별 그룹화)
        session_chains = _correlate_by_session(sorted_events, findings)

        # 체인 중복 제거
        chains = _deduplicate_chains(chains + session_chains)

        logger.info(f"상관분석 완료: {len(chains)}개 체인 생성")
        return chains

    except Exception as e:
        logger.error(f"상관분석 중 오류 발생: {e}", exc_info=True)
        raise


def _get_default_correlation_rules() -> List[CorrelationRule]:
    """기본 상관분석 규칙 반환"""
    return [
        # 다운로드 → 실행 체인
        CorrelationRule(
            rule_id="download_exec",
            name="Download and Execute Chain",
            description="웹 다운로드 후 실행 파일 실행",
            event_a_patterns=["cmd:curl", "cmd:wget", "cmd:invoke-webrequest", "cmd:download"],
            event_b_patterns=["source:ProcessCreate", "event_id:4688"],
            time_window_seconds=600,  # 10분
            required_fields=["host"],
            chain_type="download_exec",
        ),
        # 인코딩된 명령 → 실행
        CorrelationRule(
            rule_id="encoded_exec",
            name="Encoded Command Execution",
            description="인코딩된 PowerShell 명령 실행",
            event_a_patterns=["cmd:-encodedcommand", "cmd:-enc"],
            event_b_patterns=["source:ProcessCreate"],
            time_window_seconds=60,  # 1분
            required_fields=["host", "user"],
            chain_type="encoded_exec",
        ),
        # 네트워크 연결 → 데이터 전송
        CorrelationRule(
            rule_id="network_data",
            name="Network Connection and Data Transfer",
            description="네트워크 연결 후 데이터 전송",
            event_a_patterns=["source:NetworkConnection", "event_id:5156"],
            event_b_patterns=["source:NetworkTransfer", "cmd:bitsadmin"],
            time_window_seconds=300,  # 5분
            required_fields=["host"],
            chain_type="network_data",
        ),
    ]




def _calculate_chain_confidence(
    events: List[Event],
    findings: List[Finding],
    time_span: Optional[timedelta] = None
) -> float:
    """
    체인의 신뢰도 계산 (개선된 알고리즘)

    Args:
        events: 체인 내 이벤트 목록
        findings: 연관된 탐지 결과 목록
        time_span: 체인의 시간 간격

    Returns:
        신뢰도 (0.0 ~ 1.0)
    """
    if not events:
        return 0.0

    import math

    confidence = 0.3  # 기본값

    # 시간 간격이 짧을수록 신뢰도 증가
    if time_span:
        seconds = time_span.total_seconds()
        if seconds < 60:  # 1분 이내
            confidence += 0.2
        elif seconds < 300:  # 5분 이내
            confidence += 0.1
        elif seconds < 600:  # 10분 이내
            confidence += 0.05

    # Finding 심각도 가중치
    severity_weights = {
        "critical": 0.3,
        "high": 0.2,
        "medium": 0.1,
        "low": 0.05
    }
    for finding in findings:
        weight = severity_weights.get(finding.severity.lower(), 0.05)
        confidence += min(0.2, weight)  # 최대 0.2까지

    # 이벤트 개수 (로그 스케일)
    if len(events) >= 3:
        confidence += min(0.2, math.log(len(events) + 1) * 0.05)

    # Finding 개수
    if findings:
        confidence += min(0.1, len(findings) * 0.02)

    return min(1.0, confidence)


def _deduplicate_chains(chains: List[EventChain]) -> List[EventChain]:
    """
    중복 체인 제거
    같은 이벤트 집합을 포함하는 체인을 병합하거나 제거합니다.
    """
    if not chains:
        return []

    seen_chain_keys: Set[Tuple[str, ...]] = set()
    unique_chains: List[EventChain] = []

    for chain in chains:
        # 체인을 이벤트 키 집합으로 표현
        event_keys = tuple(sorted(get_event_identity_key(e) for e in chain.events))
        chain_key = (chain.chain_type, event_keys)

        if chain_key not in seen_chain_keys:
            seen_chain_keys.add(chain_key)
            unique_chains.append(chain)
        else:
            # 중복 체인 발견 - 신뢰도가 높은 것을 유지
            for existing_chain in unique_chains:
                existing_keys = tuple(sorted(get_event_identity_key(e) for e in existing_chain.events))
                if (existing_chain.chain_type, existing_keys) == (chain.chain_type, event_keys):
                    if chain.confidence > existing_chain.confidence:
                        # 더 높은 신뢰도로 교체
                        unique_chains.remove(existing_chain)
                        unique_chains.append(chain)
                        break

    return unique_chains


def find_chains_by_type(chains: List[EventChain], chain_type: str) -> List[EventChain]:
    """특정 타입의 체인만 필터링"""
    return [c for c in chains if c.chain_type == chain_type]


def get_chain_summary(chains: List[EventChain]) -> Dict[str, Any]:
    """체인 요약 통계 반환"""
    if not chains:
        return {
            "total_chains": 0,
            "by_type": {},
            "avg_confidence": 0.0,
            "total_events_in_chains": 0,
        }

    by_type: Dict[str, int] = defaultdict(int)
    total_confidence = 0.0
    total_events = 0

    for chain in chains:
        by_type[chain.chain_type] += 1
        total_confidence += chain.confidence
        total_events += len(chain.events)

    return {
        "total_chains": len(chains),
        "by_type": dict(by_type),
        "avg_confidence": total_confidence / len(chains) if chains else 0.0,
        "total_events_in_chains": total_events,
    }
# BREACHSCOPE_P0_04_MULTI_MEMBERSHIP_V1
# Correlation is evidence-centric, not ownership-centric:
# evidence may participate in multiple valid chains when independent
# correlation rules or hypotheses are satisfied.

# BREACHSCOPE_P0_07_CANONICAL_SOURCE_BRIDGE_V1
# Preserve legacy source/event_id/cmd matching first. When legacy source text
# cannot express the provider-neutral event type (for example a real Sysmon
# provider versus "ProcessCreate"), fall back to P0-02 canonical taxonomy.
def _normalize_source_token(value):
    if value is None:
        return ""
    return "".join(ch for ch in str(value).casefold() if ch.isalnum())


def _canonical_source_tokens(event):
    raw = getattr(event, "raw", None)
    if not isinstance(raw, dict):
        return set()

    canonical = raw.get("canonical")
    if not isinstance(canonical, dict):
        return set()

    event_meta = canonical.get("event")
    if not isinstance(event_meta, dict):
        return set()

    category = str(event_meta.get("category") or "").strip().casefold()
    action = str(event_meta.get("action") or "").strip().casefold()
    provider = str(event_meta.get("provider") or "").strip()

    tokens = set()

    # Canonical vocabulary itself is matchable for future correlation rules.
    for value in (category, action, provider):
        normalized = _normalize_source_token(value)
        if normalized:
            tokens.add(normalized)

    # Compatibility aliases for the abstract source taxonomy already used by
    # BreachScope correlation rules and demo data.
    aliases = {
        ("process", "process_start"): {
            "ProcessCreate",
            "ProcessStart",
        },
        ("network", "connection"): {
            "NetworkConnection",
        },
        ("authentication", "logon_success"): {
            "LogonSuccess",
            "AuthenticationSuccess",
        },
        ("authentication", "logon_failure"): {
            "LogonFailure",
            "AuthenticationFailure",
        },
        ("task", "task_create"): {
            "TaskCreate",
            "ScheduledTaskCreate",
        },
        ("log", "log_clear"): {
            "LogClear",
            "EventLogClear",
        },
        ("script", "script_block"): {
            "ScriptBlock",
            "PowerShellScriptBlock",
        },
        ("service", "service_install"): {
            "ServiceInstall",
            "ServiceCreate",
        },
    }

    for alias in aliases.get((category, action), set()):
        tokens.add(_normalize_source_token(alias))

    return tokens


def _match_canonical_source(event, patterns):
    canonical_tokens = _canonical_source_tokens(event)
    if not canonical_tokens:
        return False

    for pattern in patterns or []:
        if not isinstance(pattern, str):
            continue

        if pattern.startswith("source:"):
            requested = pattern[7:]
        elif not (
            pattern.startswith("event_id:")
            or pattern.startswith("cmd:")
        ):
            # Legacy _match_event_pattern treats a bare string as a source
            # substring, so preserve equivalent canonical fallback semantics.
            requested = pattern
        else:
            continue

        requested_token = _normalize_source_token(requested)
        if requested_token and requested_token in canonical_tokens:
            return True

    return False


# BREACHSCOPE_P2_07I_EXPLICIT_SESSION_CORRELATION_V2
# Explicit Windows logon sessions require a concrete session identifier.
# Non-authentication events without one may form bounded host/user activity chains.
_BS_P207I_ACTIVITY_WINDOW = timedelta(minutes=30)
_BS_P207I_AUTH_EVENT_IDS = {"4624", "4634", "4625", "4647"}
_BS_P207I_INVALID_SESSION_IDS = {"0", "0x0", "-", "none", "null"}


def _canonicalize_session_id(session_id) -> Optional[str]:
    """Canonicalize valid hexadecimal Windows session identifiers."""
    value = str(session_id).strip()
    if value[:2].casefold() == "0x":
        digits = value[2:]
        if not digits or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
            return None
        return f"0x{int(digits, 16):x}"
    return value


def _explicit_session_id(event: Event) -> Optional[str]:
    """Return the authoritative explicit Windows logon-session identifier."""
    raw = event.raw if isinstance(event.raw, dict) else {}
    event_id = getattr(event, "event_id", None)

    # Native lifecycle events use TargetLogonId when the field is present.
    # A concrete but invalid TargetLogonId must not fall back to compatibility aliases.
    if event_id in ("4624", "4634", "4647") and "TargetLogonId" in raw:
        value = raw.get("TargetLogonId")
        if value is None or not str(value).strip():
            return None
        canonical = _canonicalize_session_id(value)
        if not canonical or canonical.casefold() in _BS_P207I_INVALID_SESSION_IDS:
            return None
        return canonical

    if event_id not in ("4624", "4634"):
        return None

    for key in ("SessionId", "session_id"):
        value = raw.get(key)
        if value is None:
            continue
        canonical = _canonicalize_session_id(value)
        if canonical and canonical.casefold() not in _BS_P207I_INVALID_SESSION_IDS:
            return canonical
    return None


def _findings_for_events(
    events: List[Event],
    findings: List[Finding],
) -> List[Finding]:
    event_keys = {get_event_identity_key(event) for event in events}
    return [
        finding
        for finding in findings
        if get_event_identity_key(finding.event) in event_keys
    ]


def _activity_segments(events: List[Event]) -> List[List[Event]]:
    timestamped = []
    for event in events:
        timestamp = _parse_timestamp(event.timestamp)
        if timestamp is not None:
            timestamped.append((timestamp, event))

    timestamped.sort(key=lambda item: item[0])
    segments: List[List[Event]] = []
    current: List[Event] = []
    segment_start: Optional[datetime] = None

    for timestamp, event in timestamped:
        if not current:
            current = [event]
            segment_start = timestamp
            continue
        if segment_start is not None and timestamp - segment_start <= _BS_P207I_ACTIVITY_WINDOW:
            current.append(event)
            continue
        if len(current) >= 2:
            segments.append(current)
        current = [event]
        segment_start = timestamp

    if len(current) >= 2:
        segments.append(current)
    return segments


def _correlate_unscoped_session_activity(
    events: List[Event],
    findings: List[Finding],
) -> List[EventChain]:
    """Build one-id session chains plus bounded host/user activity chains."""
    session_groups: Dict[str, List[Event]] = defaultdict(list)
    activity_groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)

    for event in events:
        session_id = _explicit_session_id(event)
        if session_id:
            session_groups[session_id].append(event)
            continue
        if event.event_id in _BS_P207I_AUTH_EVENT_IDS:
            continue
        host = (event.host or "").strip()
        user = (event.user or "").strip()
        if host and user:
            activity_groups[(host.casefold(), user.casefold())].append(event)

    chains: List[EventChain] = []
    for session_id, grouped_events in sorted(session_groups.items()):
        session_events = [event for event in grouped_events if _parse_timestamp(event.timestamp)]
        session_events.sort(key=lambda event: _parse_timestamp(event.timestamp))
        if len(session_events) < 2:
            continue
        session_findings = _findings_for_events(session_events, findings)
        start_time = _parse_timestamp(session_events[0].timestamp)
        end_time = _parse_timestamp(session_events[-1].timestamp)
        chains.append(
            EventChain(
                chain_id=f"session_{session_id}",
                events=session_events,
                findings=session_findings,
                start_time=start_time,
                end_time=end_time,
                description=f"세션 {session_id}의 활동",
                confidence=0.7,
                chain_type="session",
            )
        )

    activity_number = 0
    for _, grouped_events in sorted(activity_groups.items()):
        for activity_events in _activity_segments(grouped_events):
            activity_number += 1
            start_time = _parse_timestamp(activity_events[0].timestamp)
            end_time = _parse_timestamp(activity_events[-1].timestamp)
            activity_findings = _findings_for_events(activity_events, findings)
            time_span = end_time - start_time if start_time is not None and end_time is not None else None
            chains.append(
                EventChain(
                    chain_id=f"activity_{activity_number}",
                    events=activity_events,
                    findings=activity_findings,
                    start_time=start_time,
                    end_time=end_time,
                    description="동일 호스트/사용자의 30분 이내 활동 묶음",
                    confidence=_calculate_chain_confidence(activity_events, activity_findings, time_span),
                    chain_type="activity",
                )
            )
    return chains


def _session_lifecycle_segments(grouped_events: List[Event]) -> List[List[Event]]:
    """Split one host/session-id group at authoritative logon boundaries."""
    timestamped = []
    seen_event_keys = set()
    for event in grouped_events:
        event_key = str(get_event_identity_key(event))
        if event_key in seen_event_keys:
            continue
        seen_event_keys.add(event_key)
        timestamp = _parse_timestamp(event.timestamp)
        if timestamp is not None:
            timestamped.append((timestamp, event))

    event_order = {"4624": 0, "4647": 1, "4634": 2}
    timestamped.sort(
        key=lambda item: (
            item[0],
            event_order.get(item[1].event_id, 1),
            str(get_event_identity_key(item[1])),
        )
    )

    segments: List[List[Event]] = []
    current: List[Event] = []
    for _, event in timestamped:
        if event.event_id == "4624":
            if len(current) >= 2:
                segments.append(current)
            current = [event]
            continue
        if event.event_id == "4647" and current:
            current.append(event)
            continue
        if event.event_id == "4634" and current:
            current.append(event)
            segments.append(current)
            current = []
    if len(current) >= 2:
        segments.append(current)
    return segments


def _session_lifecycle_token(events: List[Event]) -> str:
    first_identity = str(get_event_identity_key(events[0])).encode("utf-8")
    return hashlib.sha256(first_identity).hexdigest()[:10]


def _correlate_by_session(
    events: List[Event],
    findings: List[Finding],
) -> List[EventChain]:
    """Build host-scoped, lifecycle-bounded Windows session chains."""
    explicit_groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    fallback_events: List[Event] = []

    for event in events or []:
        session_id = _explicit_session_id(event)
        if not session_id:
            fallback_events.append(event)
            continue
        host = (getattr(event, "host", None) or "").strip()
        if host:
            explicit_groups[(host.casefold(), session_id)].append(event)

    chains: List[EventChain] = []
    for (host_key, session_id), grouped_events in sorted(explicit_groups.items()):
        lifecycles = _session_lifecycle_segments(grouped_events)
        logon_starts = {
            str(get_event_identity_key(event))
            for event in grouped_events
            if event.event_id == "4624"
        }
        reused_id = len(lifecycles) > 1 or len(logon_starts) > 1

        for lifecycle_events in lifecycles:
            lifecycle_chains = _correlate_unscoped_session_activity(lifecycle_events, findings)
            for chain in lifecycle_chains:
                if chain.chain_type != "session" or not chain.events:
                    continue
                base_id = f"session_{host_key}_{session_id}"
                if reused_id:
                    base_id = f"{base_id}_{_session_lifecycle_token(chain.events)}"
                    chain.session_instance_id = base_id
                chain.chain_id = base_id
                chain.description = f"호스트 {host_key} 세션 {session_id}의 활동"
            chains.extend(lifecycle_chains)

    chains.extend(_correlate_unscoped_session_activity(fallback_events, findings))
    return chains


# BREACHSCOPE_P2_07M_HOST_SCOPED_SESSION_CHAINS_V1
# BREACHSCOPE_P2_07N_SESSION_LIFECYCLE_BOUNDARIES_V1
# BREACHSCOPE_P2_07O_CANONICAL_SESSION_IDS_V1
# BREACHSCOPE_P2_07P_USER_INITIATED_LOGOFF_V1
# BREACHSCOPE_P2_07Q_TARGET_LOGON_ID_PRECEDENCE_V1
# BREACHSCOPE_P2_07V_REJECT_MALFORMED_HEX_SESSION_IDS_V1
# BREACHSCOPE_P2_07W_SESSION_LIFECYCLE_IDENTITY_V1
# BREACHSCOPE_P2_07Y_INCOMPLETE_REUSE_LIFECYCLE_MARKER_V1
# BREACHSCOPE_P2_07Z_DEDUPLICATE_SESSION_LIFECYCLE_EVENTS_V1
