"""
이벤트 수집 모듈
JSONL 파일에서 이벤트를 읽어 Event 객체로 변환합니다.
"""
from pathlib import Path
from typing import Any, Iterator, Mapping
import json
import logging
import time
from .schemas import Event
from .canonical import enrich_event_dict

logger = logging.getLogger(__name__)


def _lookup_ci(mapping: Mapping[str, Any], *names: str) -> Any:
    folded = {str(key).casefold(): value for key, value in mapping.items()}
    for name in names:
        if name in mapping and mapping[name] not in (None, ""):
            return mapping[name]
        value = folded.get(name.casefold())
        if value not in (None, ""):
            return value
    return None


def _entity_scalar(value: Any, kind: str) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, Mapping):
        return str(value)
    if kind == "host":
        value = _lookup_ci(value, "name", "hostname", "computer_name")
        return str(value) if value not in (None, "") else ""
    if kind == "user":
        name = _lookup_ci(value, "name", "username")
        domain = _lookup_ci(value, "domain")
        if name not in (None, ""):
            return f"{domain}\\{name}" if domain not in (None, "") else str(name)
        identifier = _lookup_ci(value, "id", "identifier")
        return str(identifier) if identifier not in (None, "") else ""
    if kind == "source":
        value = _lookup_ci(value, "name", "provider")
        return str(value) if value not in (None, "") else ""
    return ""


def _event_from_json_record(obj: Mapping[str, Any]) -> Event:
    event_data = obj.get("event_data")
    if not isinstance(event_data, Mapping):
        event_data = {}

    endpoint = _lookup_ci(obj, "computer_name", "Hostname", "Computer")
    host = str(endpoint) if endpoint not in (None, "") else _entity_scalar(
        _lookup_ci(obj, "host", "computer"), "host"
    )
    source_value = _lookup_ci(obj, "source_name", "SourceName", "source", "provider", "ProviderName")
    source = _entity_scalar(source_value, "source") if isinstance(source_value, Mapping) else str(source_value or "")
    timestamp = _lookup_ci(obj, "timestamp", "@timestamp", "UtcTime", "EventTime", "time_created", "TimeCreated")
    event_id = _lookup_ci(obj, "event_id", "EventID", "eventid", "eid")

    user_value = _lookup_ci(obj, "user", "User", "account")
    user = _entity_scalar(user_value, "user")
    if not user:
        user = str(_lookup_ci(event_data, "User", "SubjectUserName", "TargetUserName", "AccountName", "UserName") or "")

    command_line = _lookup_ci(obj, "command_line", "CommandLine", "ProcessCommandLine", "cmdline")
    if command_line in (None, ""):
        command_line = _lookup_ci(event_data, "CommandLine", "ProcessCommandLine")

    raw = dict(obj)
    flat_windows = any(
        _lookup_ci(obj, key) not in (None, "")
        for key in ("computer_name", "Hostname", "SourceName", "source_name", "EventID", "Channel", "log_name", "RecordNumber", "record_number")
    )
    if flat_windows:
        channel = _lookup_ci(obj, "Channel", "channel", "log_name")
        record_id = _lookup_ci(obj, "EventRecordID", "event_record_id", "RecordNumber", "record_number")
        if channel not in (None, ""):
            raw.setdefault("channel", str(channel))
        if record_id not in (None, ""):
            raw.setdefault("event_record_id", str(record_id))

    candidate = {
        "timestamp": str(timestamp or ""),
        "host": host or "unknown",
        "source": source or "unknown",
        "event_id": str(event_id or ""),
        "level": str(_lookup_ci(obj, "level", "severity") or ""),
        "user": user,
        "command_line": None if command_line in (None, "") else str(command_line),
        "raw": raw,
    }
    if flat_windows:
        candidate = enrich_event_dict(candidate)
    return Event(**candidate)

# 다계층 아티팩트 수집 모듈 (선택적)
try:
    from .ingest import collect_multi_layer_artifacts
except ImportError:
    collect_multi_layer_artifacts = None


def load_jsonl_events(path: Path, include_artifacts: bool = False) -> Iterator[Event]:
    """
    JSONL 파일에서 이벤트를 읽어 Event 객체로 변환

    Args:
        path: JSONL 파일이 있는 디렉토리 또는 파일 경로

    Yields:
        Event: 파싱된 이벤트 객체

    Note:
        - 디렉토리인 경우 하위의 모든 .jsonl 파일을 재귀적으로 검색
        - JSON 파싱 실패 시 해당 라인은 건너뜀
        - 파일 인코딩은 UTF-8로 가정
    """
    jsonl_files = list(path.rglob("*.jsonl")) if path.is_dir() else [path] if path.suffix == ".jsonl" else []

    # 아티팩트 수집이 활성화되어 있고 JSONL 파일이 없으면 아티팩트 수집 시도
    if include_artifacts and not jsonl_files and collect_multi_layer_artifacts:
        try:
            artifacts_dir = collect_multi_layer_artifacts(output_dir=path)
            if artifacts_dir:
                # 아티팩트 수집 후 다시 JSONL 파일 검색
                jsonl_files = list(artifacts_dir.rglob("*.jsonl"))
                if jsonl_files:
                    logger.info(f"아티팩트 수집 완료, {len(jsonl_files)}개 JSONL 파일 생성")
        except Exception as e:
            logger.debug(f"아티팩트 수집 실패: {e}")

    if not jsonl_files:
        logger.warning(f"JSONL 파일을 찾을 수 없습니다: {path}")
        return

    logger.info(f"{len(jsonl_files)}개 JSONL 파일 발견")

    total_events = 0
    file_start_time = time.time()

    for p in sorted(jsonl_files):
        try:
            file_start = time.time()
            with p.open("r", encoding="utf-8") as f:
                line_count = 0
                parse_errors = 0
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        line_count += 1
                    except json.JSONDecodeError as e:
                        parse_errors += 1
                        if parse_errors <= 3:  # 처음 3개 오류만 로깅
                            logger.debug(f"JSON 파싱 실패 ({p.name}:{line_num}): {e}")
                        continue
                    try:
                        event = _event_from_json_record(obj)
                        yield event
                    except Exception as e:
                        logger.warning(f"Event 객체 생성 실패 ({p.name}:{line_num}): {e}")
                        continue
                if line_count > 0:
                    total_events += line_count
                    file_time = time.time() - file_start
                    logger.info(f"파일 처리 완료: {p.name} ({line_count}개 이벤트, {file_time:.2f}초)")
                elif parse_errors > 0:
                    logger.warning(f"파일 처리 완료: {p.name} (0개 이벤트, {parse_errors}개 파싱 오류)")
                else:
                    logger.warning(f"파일 처리 완료: {p.name} (빈 파일 또는 유효한 이벤트 없음)")
        except Exception as e:
            logger.warning(f"파일 처리 실패: {p} - {e}")
            continue

    if total_events > 0:
        total_time = max(time.time() - file_start_time, 1e-9)
        logger.info(f"총 {total_events}개 이벤트 수집 완료 (총 {total_time:.2f}초, 평균 {total_events/total_time:.0f} 이벤트/초)")
