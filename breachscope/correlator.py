"""
시간 기반 상관분석 엔진
이벤트 간 시간적 연관성과 인과관계를 분석하여 이벤트 체인을 생성합니다.
"""
import logging
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


def _match_event_pattern(event: Event, patterns: List[str]) -> bool:
    """이벤트가 패턴 목록 중 하나와 매칭되는지 확인"""
    for pattern in patterns:
        # source 매칭
        if pattern.startswith("source:"):
            if event.source and pattern[7:].lower() in event.source.lower():
                return True
        # event_id 매칭
        elif pattern.startswith("event_id:"):
            if event.event_id and pattern[9:] == event.event_id:
                return True
        # command_line 패턴 매칭
        elif pattern.startswith("cmd:"):
            if event.command_line and pattern[4:].lower() in event.command_line.lower():
                return True
        # 단순 문자열 매칭 (source에 포함)
        elif event.source and pattern.lower() in event.source.lower():
            return True
    return False


def _extract_common_key(event_a: Event, event_b: Event, fields: List[str]) -> Optional[str]:
    """두 이벤트에서 공통 키 추출 (예: 같은 파일 경로, 같은 프로세스 ID 등)"""
    for field in fields:
        val_a = None
        val_b = None

        if field == "host":
            val_a = event_a.host
            val_b = event_b.host
        elif field == "user":
            val_a = event_a.user
            val_b = event_b.user
        elif field == "command_line":
            val_a = event_a.command_line
            val_b = event_b.command_line
        else:
            val_a = event_a.raw.get(field)
            val_b = event_b.raw.get(field)

        if val_a and val_b and str(val_a).lower() == str(val_b).lower():
            return f"{field}:{val_a}"
    return None


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

        # 3. 각 상관 규칙에 대해 체인 생성 (이진 검색으로 최적화)
        for rule in correlation_rules:
            logger.debug(f"규칙 적용 중: {rule.rule_id}")

            for i, (orig_idx, event_a, ts_a) in enumerate(indexed_events):

                # 이벤트 A가 패턴과 매칭되는지 확인
                if not _match_event_pattern(event_a, rule.event_a_patterns):
                    continue

                # 시간 윈도우 계산
                window_end = ts_a + timedelta(seconds=rule.time_window_seconds)

                # 이진 검색으로 윈도우 내 이벤트 찾기 (타임스탬프 리스트 사용)
                window_start_idx = i + 1
                window_end_idx = bisect.bisect_right(
                    timestamps,
                    window_end,
                    lo=window_start_idx
                )

                chain_events = [event_a]
                chain_findings: List[Finding] = []

                # 이벤트 A와 연관된 finding 추가
                if i in finding_map:
                    chain_findings.extend(finding_map[i])

                # 윈도우 내 이벤트 검색
                for j in range(window_start_idx, window_end_idx):
                    if j >= len(indexed_events):
                        break

                    orig_idx_b, event_b, ts_b = indexed_events[j]


                    # 이벤트 B가 패턴과 매칭되는지 확인
                    if not _match_event_pattern(event_b, rule.event_b_patterns):
                        continue

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


def _correlate_by_session(
    events: List[Event],
    findings: List[Finding],
) -> List[EventChain]:
    """
    세션 기반 상관분석
    Windows 로그온 세션 ID를 기준으로 이벤트를 그룹화합니다.
    """
    # 세션 ID로 그룹화
    session_groups: Dict[str, List[Event]] = defaultdict(list)

    for event in events:
        # Windows 이벤트에서 세션 ID 추출 시도
        session_id = None

        # event_id 4624 (로그온) 또는 4634 (로그오프)에서 세션 ID 추출
        if event.event_id in ("4624", "4634", "4625"):
            # raw 데이터에서 LogonType, SessionId 등 추출
            session_id = event.raw.get("SessionId") or event.raw.get("session_id")
            if not session_id:
                # SubjectLogonId 또는 TargetLogonId 사용
                session_id = event.raw.get("SubjectLogonId") or event.raw.get("TargetLogonId")

        # 세션 ID가 없으면 호스트+사용자 조합으로 그룹화
        if not session_id:
            session_id = f"{event.host}_{event.user or 'unknown'}"

        session_groups[str(session_id)].append(event)

    chains: List[EventChain] = []

    for session_id, session_events in session_groups.items():
        if len(session_events) < 2:
            continue

        # 시간순 정렬
        session_events.sort(
            key=lambda e: _parse_timestamp(e.timestamp) or datetime.min.replace(tzinfo=None)
        )

        # 세션과 연관된 findings 찾기 (고유 키 기반)
        session_findings: List[Finding] = []
        session_event_keys = {get_event_identity_key(e) for e in session_events}
        for finding in findings:
            if get_event_identity_key(finding.event) in session_event_keys:
                session_findings.append(finding)

        start_time = _parse_timestamp(session_events[0].timestamp)
        end_time = _parse_timestamp(session_events[-1].timestamp)

        chain = EventChain(
            chain_id=f"session_{session_id}",
            events=session_events,
            findings=session_findings,
            start_time=start_time,
            end_time=end_time,
            description=f"세션 {session_id}의 활동",
            confidence=0.7,  # 세션 기반은 중간 신뢰도
            chain_type="session",
        )
        chains.append(chain)

    return chains


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
# BREACHSCOPE_P0_03_REQUIRED_FIELDS_AND_V1
# Preserve the existing correlator implementation and tighten only the
# semantics of multi-field correlation constraints.
#
# Historical behavior returned as soon as ANY required field matched.
# P0-03 requires EVERY requested field to match. A single-field rule keeps
# exactly the legacy behavior.
import functools as _bs_functools
import inspect as _bs_inspect

_extract_common_key_p0_02 = _extract_common_key


@_bs_functools.wraps(_extract_common_key_p0_02)
def _extract_common_key(*args, **kwargs):
    signature = _bs_inspect.signature(_extract_common_key_p0_02)
    bound = signature.bind_partial(*args, **kwargs)

    field_param = None
    for name in signature.parameters:
        lowered = name.casefold()
        if lowered in {"fields", "required_fields"} or "field" in lowered:
            field_param = name
            break

    # If the implementation ever changes beyond the shape P0-03 understands,
    # fail open to legacy behavior rather than silently breaking correlation.
    if field_param is None or field_param not in bound.arguments:
        return _extract_common_key_p0_02(*args, **kwargs)

    fields = bound.arguments[field_param]
    if fields is None or isinstance(fields, str):
        return _extract_common_key_p0_02(*args, **kwargs)

    try:
        required = list(fields)
    except TypeError:
        return _extract_common_key_p0_02(*args, **kwargs)

    if len(required) <= 1:
        return _extract_common_key_p0_02(*args, **kwargs)

    matched_parts = []
    for field in required:
        call_bound = signature.bind_partial(*args, **kwargs)
        call_bound.arguments[field_param] = [field]
        result = _extract_common_key_p0_02(
            *call_bound.args,
            **call_bound.kwargs,
        )
        if not result:
            return None
        matched_parts.append(str(result))

    return " && ".join(matched_parts)

# BREACHSCOPE_P0_04_MULTI_MEMBERSHIP_V1
# Correlation is evidence-centric, not ownership-centric:
# evidence may participate in multiple valid chains when independent
# correlation rules or hypotheses are satisfied.

# BREACHSCOPE_P0_07_CANONICAL_SOURCE_BRIDGE_V1
# Preserve legacy source/event_id/cmd matching first. When legacy source text
# cannot express the provider-neutral event type (for example a real Sysmon
# provider versus "ProcessCreate"), fall back to P0-02 canonical taxonomy.
_match_event_pattern_p0_06 = _match_event_pattern


def _bs_p007_norm_source_token(value):
    if value is None:
        return ""
    return "".join(ch for ch in str(value).casefold() if ch.isalnum())


def _bs_p007_canonical_source_tokens(event):
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
        normalized = _bs_p007_norm_source_token(value)
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
        tokens.add(_bs_p007_norm_source_token(alias))

    return tokens


def _bs_p007_match_canonical_source(event, patterns):
    canonical_tokens = _bs_p007_canonical_source_tokens(event)
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

        requested_token = _bs_p007_norm_source_token(requested)
        if requested_token and requested_token in canonical_tokens:
            return True

    return False


def _match_event_pattern(event, patterns):
    if _match_event_pattern_p0_06(event, patterns):
        return True
    return _bs_p007_match_canonical_source(event, patterns)
