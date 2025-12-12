"""
레지스트리 아티팩트 수집 모듈
Windows 레지스트리에서 자동실행 항목, 최근 파일 목록 등을 추출합니다.
"""
import platform
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def collect_registry(
    output_dir: Optional[Path] = None,
    registry_hives: Optional[List[Path]] = None,
) -> List[Dict]:
    """
    레지스트리 아티팩트 수집

    Args:
        output_dir: 출력 디렉토리 (사용하지 않음, 호환성용)
        registry_hives: 레지스트리 하이브 파일 경로 목록 (None이면 라이브 레지스트리 조회)

    Returns:
        정규화된 이벤트 목록
    """
    if platform.system() != "Windows":
        logger.warning("레지스트리 수집은 Windows에서만 지원됩니다.")
        return []

    events = []

    # 라이브 레지스트리 조회 (reg.exe 사용)
    if registry_hives is None:
        events.extend(_collect_live_registry())
    else:
        # 오프라인 레지스트리 하이브 파일 파싱
        for hive_path in registry_hives:
            try:
                hive_events = _parse_registry_hive(hive_path)
                events.extend(hive_events)
            except Exception as e:
                logger.error(f"레지스트리 하이브 파싱 실패: {hive_path} - {e}")

    logger.info(f"레지스트리 이벤트 {len(events)}개 수집 완료")
    return events


def _collect_live_registry() -> List[Dict]:
    """라이브 레지스트리에서 자동실행 항목 수집"""
    import subprocess

    events = []

    # 자동실행 레지스트리 키 목록
    autorun_keys = [
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "autorun_hklm_run"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "autorun_hklm_runonce"),
        (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "autorun_hkcu_run"),
        (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "autorun_hkcu_runonce"),
    ]

    for key_path, event_type in autorun_keys:
        try:
            # reg.exe를 사용하여 레지스트리 값 조회
            result = subprocess.run(
                ["reg.exe", "query", key_path],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                # 레지스트리 출력 파싱
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith(key_path) or line.startswith("---"):
                        continue

                    # 값 이름과 데이터 추출
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        value_name = parts[0]
                        value_type = parts[1]
                        value_data = parts[2] if len(parts) > 2 else ""

                        event = {
                            "timestamp": datetime.now().isoformat(),
                            "host": "",
                            "source": "Registry",
                            "event_id": event_type,
                            "event_type": "autorun_entry",
                            "user": "",
                            "command_line": value_data,
                            "raw": {
                                "registry_key": key_path,
                                "value_name": value_name,
                                "value_type": value_type,
                                "value_data": value_data,
                            },
                        }
                        events.append(event)
        except Exception as e:
            logger.debug(f"레지스트리 키 조회 실패: {key_path} - {e}")
            continue

    return events


def _parse_registry_hive(hive_path: Path) -> List[Dict]:
    """
    오프라인 레지스트리 하이브 파일 파싱

    실제 구현은 python-registry 같은 라이브러리가 필요하지만,
    여기서는 기본 구조만 제공합니다.
    """
    # TODO: python-registry 라이브러리를 사용한 실제 파싱 구현
    logger.warning("오프라인 레지스트리 하이브 파싱은 아직 구현되지 않았습니다.")
    return []



