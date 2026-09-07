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


def _usb_instance_from_registry_key_line(line: str) -> Optional[Dict[str, str]]:
    """USB instance registry key line에서 source key identity를 추출합니다."""
    stripped = line.strip()
    upper = stripped.upper()
    marker = "\\ENUM\\USB\\"

    if not upper.startswith("HKEY_") or marker not in upper:
        return None

    marker_index = upper.index(marker)
    suffix = stripped[marker_index + len(marker):].strip("\\")
    parts = [part for part in suffix.split("\\") if part]

    # Enum\USB\<hardware-id>\<instance-id> 바로 아래 instance key만 사용합니다.
    # Device Parameters 같은 더 깊은 하위 키의 이름을 장치 ID로 오인하지 않습니다.
    if len(parts) != 2:
        return None

    return {
        "hardware_id": parts[0],
        "device_id": parts[1],
        "registry_key": stripped,
    }


def _device_id_from_registry_key_line(line: str) -> Optional[str]:
    """USB instance registry key line에서 device instance ID를 추출합니다."""
    instance = _usb_instance_from_registry_key_line(line)
    if instance is None:
        return None
    return instance["device_id"]


def collect_usb_history(
    output_dir: Optional[Path] = None,
) -> List[Dict]:
    """Windows 레지스트리에서 USB 장치 항목을 관측합니다.

    Args:
        output_dir: 출력 디렉토리 (사용하지 않음, 호환성용)

    Returns:
        USB 레지스트리 관측 이벤트 목록. 현재 구현은 실제 USB 연결 시각을
        추출하지 않으며 ``timestamp``는 명시적으로 수집 관측 시각을 뜻합니다.
        같은 device instance의 ``FriendlyName``과 ``DeviceDesc``는 하나의 이벤트
        ``raw.properties``에 함께 보존합니다.
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

            observed_instances: Dict[str, Dict] = {}
            current_instance: Optional[Dict[str, str]] = None

            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue

                if line.upper().startswith("HKEY_"):
                    current_instance = _usb_instance_from_registry_key_line(line)
                    if current_instance is not None:
                        observed_instances.setdefault(
                            current_instance["registry_key"],
                            {
                                **current_instance,
                                "properties": {},
                            },
                        )
                    continue

                if current_instance and "REG_" in line:
                    parts = line.split(None, 2)
                    if len(parts) < 3:
                        continue

                    prop_name = parts[0]
                    prop_value = parts[2]
                    if prop_name not in ("FriendlyName", "DeviceDesc"):
                        continue

                    observed_instances[current_instance["registry_key"]]["properties"][
                        prop_name
                    ] = prop_value

            for instance in observed_instances.values():
                properties = instance["properties"]
                if not properties:
                    continue

                primary_property = (
                    "FriendlyName" if "FriendlyName" in properties else "DeviceDesc"
                )
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
                            "instance_registry_key": instance["registry_key"],
                            "hardware_id": instance["hardware_id"],
                            "device_id": instance["device_id"],
                            "property": primary_property,
                            "value": properties[primary_property],
                            "properties": dict(properties),
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
