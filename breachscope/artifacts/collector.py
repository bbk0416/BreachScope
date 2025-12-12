"""
아티팩트 수집기 기본 클래스
"""
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ArtifactCollector:
    """아티팩트 수집기 기본 클래스"""

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Args:
            output_dir: 수집된 아티팩트를 저장할 디렉토리
        """
        if output_dir:
            self.output_dir = Path(output_dir)
            self.output_dir.mkdir(parents=True, exist_ok=True)
        else:
            import tempfile
            self.output_dir = Path(tempfile.mkdtemp(prefix="breachscope_artifacts_"))

        self.collected_artifacts: List[Dict] = []

    def collect(self, profile: str = "default") -> List[Dict]:
        """
        아티팩트 수집 실행

        Args:
            profile: 수집 프로파일 ("default", "comprehensive", "minimal")

        Returns:
            수집된 아티팩트 목록 (정규화된 이벤트 형식)
        """
        raise NotImplementedError("서브클래스에서 구현해야 합니다")

    def normalize(self, artifact: Dict) -> Dict:
        """
        아티팩트를 표준 이벤트 형식으로 정규화

        Args:
            artifact: 원시 아티팩트 데이터

        Returns:
            정규화된 이벤트 딕셔너리
        """
        return {
            "timestamp": artifact.get("timestamp", ""),
            "host": artifact.get("host", ""),
            "source": artifact.get("source", ""),
            "event_id": artifact.get("event_id", ""),
            "event_type": artifact.get("event_type", ""),
            "user": artifact.get("user", ""),
            "command_line": artifact.get("command_line", ""),
            "raw": artifact,
        }



