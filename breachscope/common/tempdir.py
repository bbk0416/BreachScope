"""
임시 디렉토리 관리 유틸리티
일관된 임시 디렉토리 생성 및 권한 처리
"""
import os
import tempfile
import random
import time
from pathlib import Path
from typing import Optional, List, Callable
import logging

from .paths import get_project_root

logger = logging.getLogger(__name__)


def create_temp_directory(
    prefix: str = "breachscope_",
    base_dir: Optional[Path] = None,
    fallback_dirs: Optional[List[Callable[[], Path]]] = None,
) -> Path:
    """
    임시 디렉토리 생성 (권한 문제 해결 포함)

    여러 위치를 시도하여 권한 문제를 최소화합니다.

    Args:
        prefix: 디렉토리 이름 접두사
        base_dir: 기본 디렉토리 (None이면 자동 선택)
        fallback_dirs: 대체 디렉토리 생성 함수 리스트

    Returns:
        생성된 임시 디렉토리 Path 객체

    Raises:
        OSError: 모든 위치에서 생성 실패 시
    """
    if fallback_dirs is None:
        # 기본 대체 디렉토리 목록
        project_root = get_project_root()
        current_pid = os.getpid()
        current_timestamp = int(time.time())
        random_suffix = random.randint(1000, 9999)

        fallback_dirs = [
            lambda: project_root / f".{prefix}temp" / f"{prefix}{current_pid}_{current_timestamp}_{random_suffix}",
            lambda: Path.cwd() / f".{prefix}temp" / f"{prefix}{current_pid}_{current_timestamp}_{random_suffix}",
            lambda: Path.home() / f".{prefix}temp" / f"{prefix}{current_pid}_{current_timestamp}_{random_suffix}",
            lambda: Path(tempfile.gettempdir()) / f"{prefix}{current_pid}_{current_timestamp}_{random_suffix}",
        ]

    # base_dir이 지정된 경우 먼저 시도
    if base_dir is not None:
        base_dir = Path(base_dir)
        try:
            if not base_dir.exists():
                base_dir.mkdir(parents=True, exist_ok=True)

            # 쓰기 권한 확인
            test_file = base_dir / ".test_write"
            test_file.write_text("test")
            test_file.unlink()

            logger.info(f"임시 디렉토리 생성 성공 (지정된 경로): {base_dir}")
            return base_dir
        except (PermissionError, OSError) as e:
            logger.warning(f"지정된 디렉토리 생성 실패: {base_dir} - {e}, 대체 위치 시도...")

    # 대체 디렉토리 시도
    for idx, create_dir in enumerate(fallback_dirs, 1):
        try:
            candidate_dir = create_dir()
            if not candidate_dir.exists():
                candidate_dir.mkdir(parents=True, exist_ok=True)

            # 쓰기 권한 확인
            test_file = candidate_dir / ".test_write"
            test_file.write_text("test")
            test_file.unlink()

            logger.info(f"임시 디렉토리 생성 성공 (방법 {idx}): {candidate_dir}")
            return candidate_dir
        except (PermissionError, OSError) as e:
            logger.warning(f"임시 디렉토리 생성 실패 (방법 {idx}): {e}, 다음 방법 시도...")
            # 실패한 디렉토리 정리 시도
            try:
                if candidate_dir.exists():
                    candidate_dir.rmdir()
            except:
                pass
            continue

    # 모든 방법 실패
    error_msg = "모든 임시 디렉토리 생성 방법 실패. 관리자 권한으로 실행하거나 디스크 공간을 확인하세요."
    logger.error(error_msg)
    raise OSError(error_msg)


def verify_write_permission(directory: Path) -> bool:
    """
    디렉토리 쓰기 권한 확인

    Args:
        directory: 확인할 디렉토리 경로

    Returns:
        쓰기 권한이 있으면 True, 없으면 False
    """
    try:
        test_file = directory / ".test_write"
        test_file.write_text("test")
        test_file.unlink()
        return True
    except (PermissionError, OSError):
        return False
