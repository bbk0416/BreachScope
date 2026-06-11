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
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
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


def _get_value(obj: Any, key: str, default: Any = "") -> Any:
    """dict와 dataclass 객체를 동일하게 다루기 위한 안전 접근자."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def calculate_event_hash(event: Any) -> str:
    """
    이벤트의 고유 해시 계산

    Args:
        event: 이벤트 dict 또는 Event 객체

    Returns:
        해시 값
    """
    key_fields = [
        _get_value(event, "timestamp", ""),
        _get_value(event, "host", ""),
        _get_value(event, "source", ""),
        _get_value(event, "event_id", ""),
        _get_value(event, "user", ""),
        _get_value(event, "command_line", ""),
    ]
    key_string = "|".join(str(f) for f in key_fields)
    return calculate_string_hash(key_string)


def calculate_finding_hash(finding: Any) -> str:
    event = _get_value(finding, "event", {})
    key_fields = [
        _get_value(finding, "rule_id", ""),
        _get_value(finding, "rule_name", ""),
        _get_value(finding, "severity", ""),
        _get_value(finding, "mitre_technique", ""),
        calculate_event_hash(event),
        _get_value(finding, "matched_value", ""),
    ]
    return calculate_string_hash("|".join(str(f) for f in key_fields))


def generate_evidence_hash_list(
    events: List[Any],
    findings: List[Any],
    chains: List[Any],
    scenarios: List[Any],
    sample_limit: Optional[int] = None,
) -> Dict[str, List[Dict]]:
    """
    증거 무결성 해시 목록 생성

    Args:
        events: 이벤트 목록
        findings: Finding 목록
        chains: Chain 목록
        scenarios: Scenario 목록
        sample_limit: 반환할 항목 수 제한. None이면 전체 반환.

    Returns:
        카테고리별 해시 목록 딕셔너리
    """
    hash_list: Dict[str, List[Dict]] = {
        "events": [],
        "findings": [],
        "chains": [],
        "scenarios": [],
    }

    def limited(items: List[Any]) -> List[Any]:
        return items if sample_limit is None else items[:sample_limit]

    for idx, event in enumerate(limited(events)):
        hash_list["events"].append({
            "index": idx,
            "hash": calculate_event_hash(event),
            "timestamp": _get_value(event, "timestamp", ""),
            "host": _get_value(event, "host", ""),
            "source": _get_value(event, "source", ""),
            "event_id": _get_value(event, "event_id", ""),
        })

    for idx, finding in enumerate(limited(findings)):
        hash_list["findings"].append({
            "index": idx,
            "hash": calculate_finding_hash(finding),
            "rule_id": _get_value(finding, "rule_id", ""),
            "severity": _get_value(finding, "severity", ""),
            "mitre_technique": _get_value(finding, "mitre_technique", ""),
        })

    for idx, chain in enumerate(limited(chains)):
        chain_key = "|".join(str(x) for x in [
            _get_value(chain, "chain_id", ""),
            _get_value(chain, "chain_type", ""),
            _get_value(chain, "start_time", ""),
            _get_value(chain, "end_time", ""),
        ])
        hash_list["chains"].append({
            "index": idx,
            "hash": calculate_string_hash(chain_key),
            "chain_id": _get_value(chain, "chain_id", ""),
            "chain_type": _get_value(chain, "chain_type", ""),
        })

    for idx, scenario in enumerate(limited(scenarios)):
        scenario_key = "|".join(str(x) for x in [
            _get_value(scenario, "scenario_id", ""),
            _get_value(scenario, "name", ""),
            _get_value(scenario, "attack_stage", ""),
        ])
        hash_list["scenarios"].append({
            "index": idx,
            "hash": calculate_string_hash(scenario_key),
            "scenario_id": _get_value(scenario, "scenario_id", ""),
            "name": _get_value(scenario, "name", ""),
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
    report_json = json.dumps(report_data, sort_keys=True, ensure_ascii=False, default=str)
    return calculate_string_hash(report_json)
