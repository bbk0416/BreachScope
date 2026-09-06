"""
Prefetch 파일 수집 모듈.

현재 구현은 Prefetch 내부 실행 시각을 파싱하지 않습니다. 대신 .pf 파일의
파일시스템 메타데이터만 수집하며, 이를 프로그램 실행 시각으로 표현하지 않습니다.
"""
from datetime import datetime
import logging
from pathlib import Path
import platform
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def collect_prefetch(
    output_dir: Optional[Path] = None,
    prefetch_dir: Optional[Path] = None,
) -> List[Dict]:
    """
    Prefetch 파일 메타데이터 수집.

    Args:
        output_dir: 출력 디렉토리 (사용하지 않음, 호환성용)
        prefetch_dir: Prefetch 디렉토리 경로 (None이면 기본 경로 사용)

    Returns:
        Prefetch 파일 관측 이벤트 목록. 현재 Prefetch 내부 실행 시각은 파싱하지
        않으며, ``timestamp``는 명시적으로 파일시스템 수정 시각을 뜻합니다.
    """
    if platform.system() != "Windows":
        logger.warning("Prefetch 수집은 Windows에서만 지원됩니다.")
        return []

    if prefetch_dir is None:
        prefetch_dir = Path("C:/Windows/Prefetch")
    else:
        prefetch_dir = Path(prefetch_dir)

    if not prefetch_dir.exists():
        logger.warning(f"Prefetch 디렉토리를 찾을 수 없습니다: {prefetch_dir}")
        return []

    events = []
    prefetch_files = list(prefetch_dir.glob("*.pf"))

    logger.info(f"Prefetch 파일 {len(prefetch_files)}개 발견")

    for pf_file in prefetch_files:
        try:
            event = _parse_prefetch_file(pf_file)
            if event:
                events.append(event)
        except Exception as e:
            logger.debug(f"Prefetch 파일 메타데이터 수집 실패: {pf_file} - {e}")
            continue

    logger.info(f"Prefetch 파일 관측 이벤트 {len(events)}개 수집 완료")
    return events


def _parse_prefetch_file(pf_path: Path) -> Optional[Dict]:
    """Prefetch 파일명과 파일시스템 메타데이터만 정규화합니다.

    이 함수는 Prefetch 내부 실행 횟수/실행 시각을 파싱하지 않습니다. 따라서
    파일의 mtime을 ``last_execution`` 또는 실제 실행 시각으로 표현하지 않습니다.
    """
    try:
        filename = pf_path.stem
        parts = filename.rsplit("-", 1)
        program_name = parts[0] if parts else filename
        filename_hash = parts[1] if len(parts) > 1 else ""

        filesystem_mtime = datetime.fromtimestamp(pf_path.stat().st_mtime).isoformat()

        return {
            "timestamp": filesystem_mtime,
            "host": "",
            "source": "Prefetch",
            "event_id": "prefetch_file_observed",
            "event_type": "artifact_observation",
            "user": "",
            "command_line": "",
            "raw": {
                "prefetch_file": str(pf_path),
                "program_name": program_name,
                "filename_hash": filename_hash,
                "filesystem_mtime": filesystem_mtime,
                "timestamp_source": "filesystem_mtime",
                "parser_mode": "metadata_only",
                "execution_time_verified": False,
                "execution_times": [],
            },
        }
    except Exception as e:
        logger.debug(f"Prefetch 파일 메타데이터 수집 오류: {pf_path} - {e}")
        return None
