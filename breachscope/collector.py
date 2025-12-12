"""
이벤트 수집 모듈
JSONL 파일에서 이벤트를 읽어 Event 객체로 변환합니다.
"""
from pathlib import Path
from typing import Iterator
import json
import logging
import time
from .schemas import Event

logger = logging.getLogger(__name__)

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
                        event = Event(
                            timestamp=str(obj.get("timestamp", "")),
                            host=str(obj.get("host", obj.get("computer", "unknown"))),
                            source=str(obj.get("source", obj.get("provider", "unknown"))),
                            event_id=str(obj.get("event_id", obj.get("eid", ""))),
                            level=str(obj.get("level", obj.get("severity", ""))),
                            user=str(obj.get("user", obj.get("account", ""))),
                            command_line=obj.get("command_line", obj.get("cmdline")),
                            raw=obj,
                        )
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
        total_time = time.time() - file_start_time
        logger.info(f"총 {total_events}개 이벤트 수집 완료 (총 {total_time:.2f}초, 평균 {total_events/total_time:.0f} 이벤트/초)")
