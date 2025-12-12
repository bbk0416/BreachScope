"""
증거 무결성 관리 모듈
SHA-256 해시 계산 및 검증 기능을 제공합니다.
"""
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> Optional[str]:
    """
    파일의 해시 값 계산

    Args:
        file_path: 파일 경로
        algorithm: 해시 알고리즘 ("sha256", "sha1", "md5")

    Returns:
        해시 값 (hex 문자열), 실패 시 None
    """
    try:
        hash_obj = hashlib.new(algorithm)
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"파일 해시 계산 실패: {file_path} - {e}")
        return None


def calculate_string_hash(text: str, algorithm: str = "sha256") -> str:
    """
    문자열의 해시 값 계산

    Args:
        text: 텍스트 문자열
        algorithm: 해시 알고리즘

    Returns:
        해시 값 (hex 문자열)
    """
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(text.encode("utf-8"))
    return hash_obj.hexdigest()


def calculate_event_hash(event: Dict) -> str:
    """
    이벤트의 고유 해시 계산

    Args:
        event: 이벤트 딕셔너리

    Returns:
        해시 값
    """
    # 이벤트의 핵심 필드를 조합하여 해시 생성
    key_fields = [
        event.get("timestamp", ""),
        event.get("host", ""),
        event.get("source", ""),
        event.get("event_id", ""),
        event.get("command_line", ""),
    ]
    key_string = "|".join(str(f) for f in key_fields)
    return calculate_string_hash(key_string)


def generate_evidence_hash_list(
    events: List[Dict],
    findings: List[Any],
    chains: List[Any],
    scenarios: List[Any],
) -> Dict[str, List[Dict]]:
    """
    증거 무결성 해시 목록 생성

    Args:
        events: 이벤트 목록
        findings: Finding 목록
        chains: Chain 목록
        scenarios: Scenario 목록

    Returns:
        카테고리별 해시 목록 딕셔너리
    """
    hash_list = {
        "events": [],
        "findings": [],
        "chains": [],
        "scenarios": [],
    }

    # 이벤트 해시
    for idx, event in enumerate(events):
        event_hash = calculate_event_hash(event if isinstance(event, dict) else event.__dict__)
        hash_list["events"].append({
            "index": idx,
            "hash": event_hash,
            "timestamp": event.get("timestamp") if isinstance(event, dict) else getattr(event, "timestamp", ""),
            "host": event.get("host") if isinstance(event, dict) else getattr(event, "host", ""),
        })

    # Finding 해시
    for idx, finding in enumerate(findings):
        finding_dict = finding.__dict__ if hasattr(finding, "__dict__") else finding
        finding_key = f"{finding_dict.get('rule_id', '')}|{finding_dict.get('event', {}).get('timestamp', '')}"
        finding_hash = calculate_string_hash(finding_key)
        hash_list["findings"].append({
            "index": idx,
            "hash": finding_hash,
            "rule_id": finding_dict.get("rule_id", ""),
            "severity": finding_dict.get("severity", ""),
        })

    # Chain 해시
    for idx, chain in enumerate(chains):
        chain_dict = chain.__dict__ if hasattr(chain, "__dict__") else chain
        chain_key = f"{chain_dict.get('chain_id', '')}|{chain_dict.get('chain_type', '')}"
        chain_hash = calculate_string_hash(chain_key)
        hash_list["chains"].append({
            "index": idx,
            "hash": chain_hash,
            "chain_id": chain_dict.get("chain_id", ""),
            "chain_type": chain_dict.get("chain_type", ""),
        })

    # Scenario 해시
    for idx, scenario in enumerate(scenarios):
        scenario_dict = scenario.__dict__ if hasattr(scenario, "__dict__") else scenario
        scenario_key = f"{scenario_dict.get('scenario_id', '')}|{scenario_dict.get('name', '')}"
        scenario_hash = calculate_string_hash(scenario_key)
        hash_list["scenarios"].append({
            "index": idx,
            "hash": scenario_hash,
            "scenario_id": scenario_dict.get("scenario_id", ""),
            "name": scenario_dict.get("name", ""),
        })

    return hash_list


def generate_report_hash(report_data: Dict) -> str:
    """
    리포트 전체의 무결성 해시 생성

    Args:
        report_data: 리포트 데이터 딕셔너리

    Returns:
        리포트 해시 값
    """
    import json
    report_json = json.dumps(report_data, sort_keys=True, ensure_ascii=False)
    return calculate_string_hash(report_json)

