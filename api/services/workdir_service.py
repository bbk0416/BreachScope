"""
작업 디렉토리 관리 서비스
"""
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import logging

from .path_boundary import resolve_user_work_dir

logger = logging.getLogger(__name__)


class WorkDirectoryService:
    """작업 디렉토리 관리 서비스"""

    def create_work_directory(self, work_dir: Optional[str] = None) -> Path:
        """
        작업 디렉토리 생성

        Args:
            work_dir: 사용자 지정 디렉토리 경로 (선택)

        Returns:
            작업 디렉토리 Path

        Raises:
            Exception: 디렉토리 생성 실패 시
        """
        # BREACHSCOPE_P0_11_WORKDIR_BOUNDARY_V1
        if work_dir and str(work_dir).strip():
            return resolve_user_work_dir(work_dir, create=True)

        # 기본은 영구 케이스 루트에 생성하여 웹 콘솔에서 분석 이력을 다시 열 수 있게 합니다.
        # 기존처럼 시스템 임시 디렉토리를 쓰고 싶으면 BS_USE_SYSTEM_TEMP=1 로 변경합니다.
        try:
            if os.getenv("BS_USE_SYSTEM_TEMP", "0") == "1":
                work = Path(tempfile.mkdtemp(prefix="bs_web_"))
                logger.info(f"시스템 임시 작업 디렉토리 생성: {work}")
                return work

            root = Path(os.getenv("BS_CASES_ROOT", str(Path.home() / ".breachscope" / "cases"))).expanduser()
            root.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            work = root / f"bs_case_{stamp}_{os.getpid()}"
            counter = 1
            while work.exists():
                work = root / f"bs_case_{stamp}_{os.getpid()}_{counter}"
                counter += 1
            work.mkdir(parents=True, exist_ok=False)
            logger.info(f"영구 케이스 작업 디렉토리 생성: {work}")
            return work
        except Exception as e:
            logger.error(f"작업 디렉토리 생성 실패: {e}")
            raise Exception("작업 디렉토리 생성 실패. 디스크 공간을 확인하거나 관리자에게 문의하세요.")
