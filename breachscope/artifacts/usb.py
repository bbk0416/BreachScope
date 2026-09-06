"""
USB 레지스트리 관측 수집 모듈.

현재 구현은 Windows 레지스트리의 USB 장치 항목을 열거하지만 실제 연결 시각을
추출하지 않습니다. 따라서 수집 시각을 USB 연결 시각으로 표현하지 않고,
레지스트리 항목을 관측한 시각으로만 기록합니다.
"""
from datetime import datetime, timezone
import logging
from pathlib import Path
import platform
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def collect_usb_history(
    output_dir: Optional[Path] = None,
) -> List[Dict]:
    """Windows 레지스트리에서 USB 장치 항목을 관측합니다.

    Args:
        output_dir: 출력 디렉토리 (사용하지 않음, 호환성용)

    Returns:
        USB 레지스트리 관측 이벤트 목록. 현재 구현은 실제 USB 연결 시각을
        추출하지 않으며 ``timestamp``는 명시적으로 수집 관측 시각을 뜻합니다.
    """
    if platform.system() != "Windows":
        logger.warning("USB 기록 수집은 Windows에서만 지원됩니다.")
        return []

    events: List[Dict] = []
    usb_keys = [r"HKLM\SYSTEM\CurrentControlSet\Enum\USB"]

    for key_path in usb_keys:
        try:
            result = subprocess.run(
                ["reg.exe", "query", key_path, "/s"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                continue

            current_device = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue

                if key_path in line and "\\" in line:
                    device_id = line.split("\\")[-1]
                    if device_id:
                        current_device = device_id

                if current_device and "    " in line and "REG_" in line:
                    parts = line.split(None, 2)
                    if len(parts) < 3:
                        continue

                    prop_name = parts[0]
                    prop_value = parts[2]
                    if prop_name not in ("FriendlyName", "DeviceDesc"):
                        continue

                    observation_time = datetime.now(timezone.utc).isoformat()
                    events.append(
                        {
                            "timestamp": observation_time,
                            "host": "",
                            "source": "USB",
                            "event_id": "usb_registry_device_observed",
                            "event_type": "artifact_observation",
                            "user": "",
                            "command_line": "",
                            "raw": {
                                "registry_key": key_path,
                                "device_id": current_device,
                                "property": prop_name,
                                "value": prop_value,
                                "observation_time": observation_time,
                                "timestamp_source": "collection_time",
                                "connection_time_verified": False,
                                "connection_times": [],
                            },
                        }
                    )
        except Exception as e:
            logger.debug(f"USB 레지스트리 관측 실패: {key_path} - {e}")
            continue

    logger.info(f"USB 레지스트리 관측 이벤트 {len(events)}개 수집 완료")
    return events
