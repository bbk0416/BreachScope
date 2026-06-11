"""
USB 연결 기록 수집 모듈
Windows 레지스트리에서 USB 장치 연결 이력을 추출합니다.
"""
import platform
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import logging
import subprocess

logger = logging.getLogger(__name__)


def collect_usb_history(
    output_dir: Optional[Path] = None,
) -> List[Dict]:
    """
    USB 연결 기록 수집

    Args:
        output_dir: 출력 디렉토리 (사용하지 않음, 호환성용)

    Returns:
        정규화된 이벤트 목록
    """
    if platform.system() != "Windows":
        logger.warning("USB 기록 수집은 Windows에서만 지원됩니다.")
        return []

    events = []

    # USB 장치 정보 레지스트리 키
    usb_keys = [
        (r"HKLM\SYSTEM\CurrentControlSet\Enum\USB", "usb_device_connected"),
    ]

    for key_path, event_type in usb_keys:
        try:
            # reg.exe를 사용하여 USB 장치 목록 조회
            result = subprocess.run(
                ["reg.exe", "query", key_path, "/s"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                current_device = None
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    # USB 장치 ID 추출
                    if key_path in line and "\\" in line:
                        device_id = line.split("\\")[-1]
                        if device_id:
                            current_device = device_id

                    # 장치 속성 추출
                    if current_device and "    " in line and "REG_" in line:
                        parts = line.split(None, 2)
                        if len(parts) >= 3:
                            prop_name = parts[0]
                            prop_value = parts[2] if len(parts) > 2 else ""

                            # FriendlyName이나 DeviceDesc 추출
                            if prop_name in ("FriendlyName", "DeviceDesc"):
                                event = {
                                    "timestamp": datetime.now().isoformat(),  # 실제로는 레지스트리 타임스탬프 사용
                                    "host": "",
                                    "source": "USB",
                                    "event_id": event_type,
                                    "event_type": "usb_device",
                                    "user": "",
                                    "command_line": f"{current_device} - {prop_value}",
                                    "raw": {
                                        "device_id": current_device,
                                        "property": prop_name,
                                        "value": prop_value,
                                    },
                                }
                                events.append(event)
        except Exception as e:
            logger.debug(f"USB 기록 수집 실패: {key_path} - {e}")
            continue

    logger.info(f"USB 이벤트 {len(events)}개 수집 완료")
    return events



