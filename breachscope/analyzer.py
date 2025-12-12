import re
import logging
from typing import Iterable, Iterator, List, Set, Tuple, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .schemas import Event, Rule, Finding
from . import decoder
from .utils import get_event_key

logger = logging.getLogger(__name__)


def apply_rules(events: Iterable[Event], rules: List[Rule]) -> Iterator[Finding]:
    compiled: List[Tuple[Rule, Callable[[str], Optional[Tuple[str, int, int]]]]] = [
        (r, _compile_rule_matcher(r)) for r in rules
    ]
    seen: Set[Tuple[str, str, str]] = set()  # (rule_id, event_key, match)
    for e in events:
        texts: List[str] = []

        # Base command line and PowerShell-specific decoding
        if e.command_line:
            texts.append(e.command_line)
            # Extract PowerShell -enc/-encodedcommand payloads and decode
            decs = _decode_powershell_encoded(e.command_line)
            texts.extend(decs)
            # 고급 디코더 사용 (PowerShell 난독화 해제)
            try:
                decoded_result = decoder.decode_powershell_obfuscation(e.command_line)
                if decoded_result["decoded"] and decoded_result["decoded"] not in texts:
                    texts.append(decoded_result["decoded"])
                    # 디코딩된 텍스트에서 악성 행위 식별
                    behaviors = decoder.identify_malicious_behavior(decoded_result["decoded"])
                    if behaviors:
                        # 악성 행위 정보를 이벤트에 추가 (나중에 리포트에 사용)
                        e.raw.setdefault("decoded_behaviors", behaviors)
            except Exception as ex:
                # 디코딩 실패 시 무시하고 계속 진행
                pass
            # As a fallback, try full-line base64 heuristic (may produce false positives)
            maybe = decoder.maybe_base64(e.command_line)
            if maybe and maybe not in texts:
                texts.append(maybe)
        # Add any raw suspicious fields if present
        for k in ("script", "payload", "message"):
            v = e.raw.get(k)
            if isinstance(v, str):
                texts.append(v)

        for rule, finder in compiled:
            # Select field content
            field_vals: List[str] = []
            # support multi-field rules
            fields = rule.fields if rule.fields else [rule.field]
            for fld in fields:
                if fld == "command_line":
                    field_vals.append(e.command_line or "")
                else:
                    field_vals.append(str(e.raw.get(fld, "")))
            # Search in decoded and raw texts
            candidates = field_vals + texts
            for c in candidates:
                if not c:
                    continue
                found = finder(c)
                if found:
                    match_val, s, eidx = found
                    key = (rule.id, get_event_key(e), match_val)
                    if key in seen:
                        break
                    seen.add(key)
                    # Build small context window around match
                    ctx_left = max(0, s - 40)
                    ctx_right = min(len(c), eidx + 40)
                    context = c[ctx_left:ctx_right]
                    yield Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        mitre_technique=rule.mitre_technique,
                        event=e,
                        matched_value=match_val,
                        matched_context=context,
                    )
                    break


def _decode_powershell_encoded(cmdline: str) -> List[str]:
    """Extract and decode common PowerShell encoded command arguments.
    - Handles -enc, -encodedcommand with optional ':' and whitespace.
    - Decodes Base64 with UTF-16LE and UTF-8 fallback.
    """
    decs: List[str] = []
    # Find tokens following -enc/-encodedcommand; accept quotes or bare token
    rx = re.compile(
        r"-(?:enc|encodedcommand)\s*[:=]?\s*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z0-9+/=]{8,}))",
        re.IGNORECASE,
    )
    for m in rx.finditer(cmdline):
        b64 = next((g for g in m.groups() if g), None)
        if not b64:
            continue
        # Strip non-base64 tails (common when followed by ; or &)
        b64 = re.split(r"[^A-Za-z0-9+/=]", b64)[0]
        dec = decoder.maybe_base64(b64)
        if dec:
            decs.append(dec)
    return decs


def _compile_rule_matcher(rule: Rule) -> Callable[[str], Optional[Tuple[str, int, int]]]:
    pat = rule.pattern or ""
    low = pat.lower()

    def ret_tuple(val: str, s: int, e: int) -> Tuple[str, int, int]:
        return (val, s, e)

    # If rule.operator is provided, prefer it over prefix notation
    operator = (rule.operator or "").lower()
    if operator == "contains" and not low.startswith("contains:"):
        low = f"contains:{pat}"
    elif operator == "startswith" and not low.startswith("startswith:"):
        low = f"startswith:{pat}"
    elif operator == "endswith" and not low.startswith("endswith:"):
        low = f"endswith:{pat}"
    elif operator == "equals" and not low.startswith("equals:"):
        low = f"equals:{pat}"
    # contains:foo|bar
    if low.startswith("contains:"):
        targets = [t for t in pat[len("contains:"):].split("|") if t]

        def find_contains(s: str) -> Optional[Tuple[str, int, int]]:
            sl = s.lower()
            for t in targets:
                idx = sl.find(t.lower())
                if idx >= 0:
                    return ret_tuple(s[idx:idx + len(t)], idx, idx + len(t))
            return None

        return find_contains

    # startswith:foo
    if low.startswith("startswith:"):
        tgt = pat[len("startswith:"):]

        def find_startswith(s: str) -> Optional[Tuple[str, int, int]]:
            if s.lower().startswith(tgt.lower()):
                return ret_tuple(s[: len(tgt)], 0, len(tgt))
            return None

        return find_startswith

    # endswith:foo
    if low.startswith("endswith:"):
        tgt = pat[len("endswith:"):]

        def find_endswith(s: str) -> Optional[Tuple[str, int, int]]:
            if s.lower().endswith(tgt.lower()):
                return ret_tuple(s[len(s) - len(tgt) :], len(s) - len(tgt), len(s))
            return None

        return find_endswith

    # equals:foo
    if low.startswith("equals:"):
        tgt = pat[len("equals:"):]

        def find_equals(s: str) -> Optional[Tuple[str, int, int]]:
            if s.lower() == tgt.lower():
                return ret_tuple(s, 0, len(s))
            return None

        return find_equals

    # default: regex
    rx = re.compile(pat, re.IGNORECASE | re.MULTILINE)

    def find_regex(s: str) -> Optional[Tuple[str, int, int]]:
        m = rx.search(s)
        if not m:
            return None
        return ret_tuple(m.group(0), m.start(), m.end())

    return find_regex


def apply_rules_parallel(
    events: List[Event],
    rules: List[Rule],
    max_workers: Optional[int] = None,
    chunk_size: int = 1000,
) -> List[Finding]:
    """
    규칙 기반 분석 실행 (병렬 처리 버전)

    Args:
        events: 분석할 이벤트 목록
        rules: 적용할 규칙 목록
        max_workers: 최대 워커 스레드 수 (None이면 CPU 코어 수)
        chunk_size: 청크 크기 (이벤트를 나눌 단위)

    Returns:
        탐지 결과 리스트
    """
    if not events or not rules:
        return []

    import os
    if max_workers is None:
        # CPU 코어 수의 2배를 기본값으로 사용 (I/O 바운드 작업 고려)
        max_workers = min(len(os.sched_getaffinity(0)) * 2, 8) if hasattr(os, 'sched_getaffinity') else os.cpu_count() or 4

    logger.info(f"병렬 분석 시작: {len(events)}개 이벤트, {len(rules)}개 규칙, {max_workers}개 워커")

    # 규칙 컴파일 (한 번만)
    compiled: List[Tuple[Rule, Callable[[str], Optional[Tuple[str, int, int]]]]] = [
        (r, _compile_rule_matcher(r)) for r in rules
    ]

    # 이벤트를 청크로 나누기
    chunks = [events[i:i + chunk_size] for i in range(0, len(events), chunk_size)]

    all_findings: List[Finding] = []
    seen: Set[Tuple[str, str, str]] = set()  # 전역 중복 제거용

    def process_chunk(chunk_events: List[Event]) -> List[Finding]:
        """청크 단위 처리"""
        chunk_findings: List[Finding] = []
        chunk_seen: Set[Tuple[str, str, str]] = set()

        for e in chunk_events:
            texts: List[str] = []

            # Base command line and PowerShell-specific decoding
            if e.command_line:
                texts.append(e.command_line)
                decs = _decode_powershell_encoded(e.command_line)
                texts.extend(decs)
                # 고급 디코더 사용
                try:
                    decoded_result = decoder.decode_powershell_obfuscation(e.command_line)
                    if decoded_result["decoded"] and decoded_result["decoded"] not in texts:
                        texts.append(decoded_result["decoded"])
                        behaviors = decoder.identify_malicious_behavior(decoded_result["decoded"])
                        if behaviors:
                            e.raw.setdefault("decoded_behaviors", behaviors)
                except Exception:
                    pass
                maybe = decoder.maybe_base64(e.command_line)
                if maybe and maybe not in texts:
                    texts.append(maybe)

            for k in ("script", "payload", "message"):
                v = e.raw.get(k)
                if isinstance(v, str):
                    texts.append(v)

            for rule, finder in compiled:
                field_vals: List[str] = []
                fields = rule.fields if rule.fields else [rule.field]
                for fld in fields:
                    if fld == "command_line":
                        field_vals.append(e.command_line or "")
                    else:
                        field_vals.append(str(e.raw.get(fld, "")))

                candidates = field_vals + texts
                for c in candidates:
                    if not c:
                        continue
                    found = finder(c)
                    if found:
                        match_val, s, eidx = found
                        key = (rule.id, get_event_key(e), match_val)
                        if key in chunk_seen:
                            break
                        chunk_seen.add(key)
                        ctx_left = max(0, s - 40)
                        ctx_right = min(len(c), eidx + 40)
                        context = c[ctx_left:ctx_right]
                        chunk_findings.append(Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            mitre_technique=rule.mitre_technique,
                            event=e,
                            matched_value=match_val,
                            matched_context=context,
                        ))
                        break

        return chunk_findings

    # 병렬 처리 실행
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_chunk = {executor.submit(process_chunk, chunk): i for i, chunk in enumerate(chunks)}

        for future in as_completed(future_to_chunk):
            try:
                chunk_findings = future.result()
                # 중복 제거 (전역 seen 사용)
                for finding in chunk_findings:
                    key = (finding.rule_id, get_event_key(finding.event), finding.matched_value)
                    if key not in seen:
                        seen.add(key)
                        all_findings.append(finding)
            except Exception as e:
                logger.error(f"청크 처리 중 오류 발생: {e}", exc_info=True)

    logger.info(f"병렬 분석 완료: {len(all_findings)}개 탐지 결과")
    return all_findings
