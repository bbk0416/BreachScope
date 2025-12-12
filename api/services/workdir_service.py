"""
작업 디렉토리 관리 서비스
"""
import os
import tempfile
import time
from pathlib import Path
from typing import Optional
import logging

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
        current_timestamp = int(time.time())
        current_pid = os.getpid()

        # 사용자가 지정한 작업 디렉토리가 있으면 우선 사용
        if work_dir and work_dir.strip():
            try:
                user_work_dir = Path(work_dir.strip())
                if not user_work_dir.is_absolute():
                    user_work_dir = Path.cwd() / user_work_dir

                if not user_work_dir.exists():
                    user_work_dir.mkdir(parents=True, exist_ok=True)

                if user_work_dir.exists() and user_work_dir.is_dir():
                    # 쓰기 권한 확인
                    try:
                        test_file = user_work_dir / ".test_write"
                        test_file.write_text("test")
                        test_file.unlink()
                        logger.info(f"사용자 지정 작업 디렉토리 사용: {user_work_dir}")
                        return user_work_dir
                    except (PermissionError, OSError) as perm_err:
                        logger.warning(f"사용자 지정 디렉토리 권한 오류: {perm_err}, 시스템 임시 디렉토리 사용...")
            except Exception as e:
                logger.warning(f"사용자 지정 작업 디렉토리 오류: {e}, 시스템 임시 디렉토리 사용...")

        # 시스템 임시 디렉토리 사용 (권한 문제 최소화)
        try:
            work = Path(tempfile.mkdtemp(prefix="bs_web_"))
            logger.info(f"시스템 임시 작업 디렉토리 생성: {work}")
            return work
        except Exception as e:
            logger.error(f"시스템 임시 디렉토리 생성 실패: {e}")
            raise Exception("작업 디렉토리 생성 실패. 디스크 공간을 확인하거나 관리자에게 문의하세요.")
