"""
아티팩트 분류 시스템 (KAPE 스타일)
수집된 아티팩트를 논리적인 카테고리별로 분류합니다.
"""
from pathlib import Path
from typing import List, Dict, Optional
from enum import Enum
import logging
import shutil

logger = logging.getLogger(__name__)


class ArtifactCategory(Enum):
    """아티팩트 카테고리"""
    EVIDENCE_OF_EXECUTION = "EvidenceOfExecution"
    BROWSER_HISTORY = "BrowserHistory"
    ACCOUNT_USAGE = "AccountUsage"
    NETWORK_ACTIVITY = "NetworkActivity"
    FILE_OPERATIONS = "FileOperations"
    REGISTRY_ARTIFACTS = "RegistryArtifacts"
    SYSTEM_CONFIGURATION = "SystemConfiguration"
    USER_ACTIVITY = "UserActivity"
    MALWARE_INDICATORS = "MalwareIndicators"
    OTHER = "Other"


class ArtifactClassifier:
    """아티팩트 분류기"""

    # 이벤트 소스/타입별 카테고리 매핑
    # classify_event()가 lookup 값을 소문자로 정규화하므로 모든 key도 소문자를 사용한다.
    CATEGORY_MAPPING = {
        # 실행 관련
        "prefetch_execution": ArtifactCategory.EVIDENCE_OF_EXECUTION,
        "program_execution": ArtifactCategory.EVIDENCE_OF_EXECUTION,
        "process_creation": ArtifactCategory.EVIDENCE_OF_EXECUTION,

        # 브라우저 관련
        "browser_visit": ArtifactCategory.BROWSER_HISTORY,
        "web_activity": ArtifactCategory.BROWSER_HISTORY,
        "chrome": ArtifactCategory.BROWSER_HISTORY,
        "edge": ArtifactCategory.BROWSER_HISTORY,
        "firefox": ArtifactCategory.BROWSER_HISTORY,

        # 계정 관련
        "logon": ArtifactCategory.ACCOUNT_USAGE,
        "logoff": ArtifactCategory.ACCOUNT_USAGE,
        "account_creation": ArtifactCategory.ACCOUNT_USAGE,
        "account_modification": ArtifactCategory.ACCOUNT_USAGE,

        # 네트워크 관련
        "network_connection": ArtifactCategory.NETWORK_ACTIVITY,
        "dns_query": ArtifactCategory.NETWORK_ACTIVITY,
        "firewall_event": ArtifactCategory.NETWORK_ACTIVITY,

        # 파일 관련
        "file_creation": ArtifactCategory.FILE_OPERATIONS,
        "file_modification": ArtifactCategory.FILE_OPERATIONS,
        "file_deletion": ArtifactCategory.FILE_OPERATIONS,
        "file_access": ArtifactCategory.FILE_OPERATIONS,

        # 레지스트리 관련
        "autorun_entry": ArtifactCategory.REGISTRY_ARTIFACTS,
        "registry_modification": ArtifactCategory.REGISTRY_ARTIFACTS,
        "registry": ArtifactCategory.REGISTRY_ARTIFACTS,

        # 시스템 설정 관련
        "system_configuration": ArtifactCategory.SYSTEM_CONFIGURATION,
        "service_installation": ArtifactCategory.SYSTEM_CONFIGURATION,
        "scheduled_task": ArtifactCategory.SYSTEM_CONFIGURATION,

        # 사용자 활동 관련
        "user_activity": ArtifactCategory.USER_ACTIVITY,
        "usb_device": ArtifactCategory.USER_ACTIVITY,
        "usb": ArtifactCategory.USER_ACTIVITY,

        # 악성 지표
        "suspicious_command": ArtifactCategory.MALWARE_INDICATORS,
        "encoded_command": ArtifactCategory.MALWARE_INDICATORS,
        "powershell_obfuscation": ArtifactCategory.MALWARE_INDICATORS,
    }

    @classmethod
    def classify_event(cls, event: Dict) -> ArtifactCategory:
        """
        이벤트를 카테고리로 분류

        Args:
            event: 이벤트 딕셔너리

        Returns:
            ArtifactCategory
        """
        # event_id로 분류 시도
        event_id = event.get("event_id", "").lower()
        if event_id in cls.CATEGORY_MAPPING:
            return cls.CATEGORY_MAPPING[event_id]

        # event_type으로 분류 시도
        event_type = event.get("event_type", "").lower()
        if event_type in cls.CATEGORY_MAPPING:
            return cls.CATEGORY_MAPPING[event_type]

        # source로 분류 시도
        source = event.get("source", "").lower()
        if source in cls.CATEGORY_MAPPING:
            return cls.CATEGORY_MAPPING[source]

        # command_line 내용으로 분류 시도
        command_line = event.get("command_line", "").lower()
        if any(keyword in command_line for keyword in ["http://", "https://", "www."]):
            return ArtifactCategory.BROWSER_HISTORY

        if any(keyword in command_line for keyword in ["powershell", "cmd.exe", "wscript"]):
            return ArtifactCategory.EVIDENCE_OF_EXECUTION

        # 기본값
        return ArtifactCategory.OTHER

    @classmethod
    def organize_artifacts(
        cls,
        events: List[Dict],
        output_dir: Path,
        create_directories: bool = True,
    ) -> Dict[ArtifactCategory, List[Dict]]:
        """
        아티팩트를 카테고리별로 분류하고 디렉토리 구조로 정리

        Args:
            events: 이벤트 목록
            output_dir: 출력 디렉토리
            create_directories: 카테고리별 디렉토리 생성 여부

        Returns:
            카테고리별 이벤트 딕셔너리
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        categorized: Dict[ArtifactCategory, List[Dict]] = {
            category: [] for category in ArtifactCategory
        }

        # 이벤트 분류
        for event in events:
            category = cls.classify_event(event)
            categorized[category].append(event)

        # 카테고리별 디렉토리 생성 및 파일 저장
        if create_directories:
            import json

            for category, category_events in categorized.items():
                if not category_events:
                    continue

                category_dir = output_dir / category.value
                category_dir.mkdir(parents=True, exist_ok=True)

                # JSONL 파일로 저장
                jsonl_path = category_dir / f"{category.value}.jsonl"
                with jsonl_path.open("w", encoding="utf-8") as f:
                    for event in category_events:
                        f.write(json.dumps(event, ensure_ascii=False) + "\n")

                logger.info(f"{category.value}: {len(category_events)}개 이벤트")

        return categorized

    @classmethod
    def get_category_summary(cls, categorized: Dict[ArtifactCategory, List[Dict]]) -> Dict[str, any]:
        """
        카테고리별 요약 정보 생성

        Args:
            categorized: 카테고리별 이벤트 딕셔너리

        Returns:
            요약 정보 딕셔너리
        """
        summary = {
            "total_events": sum(len(events) for events in categorized.values()),
            "categories": {},
        }

        for category, events in categorized.items():
            if events:
                summary["categories"][category.value] = {
                    "count": len(events),
                    "percentage": round(len(events) / summary["total_events"] * 100, 2) if summary["total_events"] > 0 else 0,
                }

        return summary


def classify_and_organize(
    events: List[Dict],
    output_dir: Path,
    create_directories: bool = True,
) -> Dict[str, any]:
    """
    아티팩트 분류 및 정리 (편의 함수)

    Args:
        events: 이벤트 목록
        output_dir: 출력 디렉토리
        create_directories: 카테고리별 디렉토리 생성 여부

    Returns:
        분류 결과 및 요약 정보
    """
    categorized = ArtifactClassifier.organize_artifacts(
        events, output_dir, create_directories
    )
    summary = ArtifactClassifier.get_category_summary(categorized)

    return {
        "categorized": categorized,
        "summary": summary,
        "output_dir": str(output_dir),
    }



