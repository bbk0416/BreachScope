"""
경로 관리 유틸리티
프로젝트 루트 경로 및 경로 설정 관리
"""
import sys
from pathlib import Path
from typing import Optional


def get_project_root() -> Path:
    """
    프로젝트 루트 디렉토리 경로 반환

    Returns:
        프로젝트 루트 Path 객체
    """
    # 현재 파일의 위치에서 프로젝트 루트 찾기
    current_file = Path(__file__).resolve()
    # breachscope/common/paths.py -> breachscope/common -> breachscope -> 프로젝트 루트
    root = current_file.parent.parent.parent
    return root


def setup_path(root: Optional[Path] = None) -> None:
    """
    프로젝트 루트를 Python 경로에 추가

    Args:
        root: 프로젝트 루트 경로 (None이면 자동 탐지)
    """
    if root is None:
        root = get_project_root()

    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
