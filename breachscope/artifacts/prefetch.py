"""
Prefetch 파일 수집 모듈
Windows Prefetch 파일에서 프로그램 실행 정보를 추출합니다.
"""
import platform
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import logging
import struct

logger = logging.getLogger(__name__)


def collect_prefetch(
    output_dir: Optional[Path] = None,
    prefetch_dir: Optional[Path] = None,
) -> List[Dict]:
    """
    Prefetch 파일 수집

    Args:
        output_dir: 출력 디렉토리 (사용하지 않음, 호환성용)
        prefetch_dir: Prefetch 디렉토리 경로 (None이면 기본 경로 사용)

    Returns:
        정규화된 이벤트 목록
    """
    if platform.system() != "Windows":
        logger.warning("Prefetch 수집은 Windows에서만 지원됩니다.")
        return []

    if prefetch_dir is None:
        # Windows 기본 Prefetch 경로
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
            # Prefetch 파일 파싱 (간단한 버전)
            # 실제로는 더 복잡한 파싱이 필요하지만, 기본 정보만 추출
            event = _parse_prefetch_file(pf_file)
            if event:
                events.append(event)
        except Exception as e:
            logger.debug(f"Prefetch 파일 파싱 실패: {pf_file} - {e}")
            continue

    logger.info(f"Prefetch 이벤트 {len(events)}개 수집 완료")
    return events


def _parse_prefetch_file(pf_path: Path) -> Optional[Dict]:
    """
    Prefetch 파일 파싱 (기본 버전)

    실제 Prefetch 파일 형식은 복잡하므로, 파일명과 수정 시간을 기반으로 기본 정보 추출
    """
    try:
        # Prefetch 파일명 형식: PROGRAMNAME-HASH.pf
        # 예: NOTEPAD.EXE-A1B2C3D4.pf
        filename = pf_path.stem
        parts = filename.rsplit("-", 1)
        program_name = parts[0] if len(parts) > 0 else filename

        # 파일 수정 시간을 마지막 실행 시간으로 사용
        mtime = datetime.fromtimestamp(pf_path.stat().st_mtime)

        return {
            "timestamp": mtime.isoformat(),
            "host": "",  # 호스트 정보는 파일 경로에서 추출 가능
            "source": "Prefetch",
            "event_id": "prefetch_execution",
            "event_type": "program_execution",
            "user": "",
            "command_line": program_name,
            "raw": {
                "prefetch_file": str(pf_path),
                "program_name": program_name,
                "hash": parts[1] if len(parts) > 1 else "",
                "last_execution": mtime.isoformat(),
            },
        }
    except Exception as e:
        logger.debug(f"Prefetch 파일 파싱 오류: {pf_path} - {e}")
        return None



