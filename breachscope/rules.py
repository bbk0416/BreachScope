"""
규칙 로딩 및 검증 모듈
YAML 규칙 파일을 로드하고 Sigma-like 규칙을 변환합니다.
"""
import yaml
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from .schemas import Rule


def parse_attack_tag(tags: Any) -> Optional[str]:
    """
    Sigma 규칙의 tags에서 MITRE ATT&CK 태그 추출

    Args:
        tags: 태그 리스트 또는 None

    Returns:
        MITRE 기법 코드 (예: "T1059.001") 또는 None
    """
    if not isinstance(tags, list):
        return None
    for t in tags:
        if not isinstance(t, str):
            continue
        tl = t.lower()
        if tl.startswith("attack.t"):
            # e.g., attack.t1059.001 -> T1059.001
            val = t.split("attack.")[-1].upper()
            return val
    return None


def sigma_like_to_rules(doc: Dict[str, Any]) -> List[Rule]:
    """
    Sigma-like 규칙을 BreachScope Rule로 변환

    지원하는 Sigma 형식:
      title, id(optional), tags(optional: attack.tXXXX) and detection:
        selection:
          CommandLine|contains: str | [str, ...]
        condition: selection

    Args:
        doc: Sigma 규칙 딕셔너리

    Returns:
        변환된 Rule 리스트
    """
    title = str(doc.get("title", "Sigma-like Rule"))
    rid = str(doc.get("id", title))
    mitre = parse_attack_tag(doc.get("tags") or [])
    det = doc.get("detection") or {}
    sel = det.get("selection") or {}
    cl_key = None

    # CommandLine|contains 필드 찾기
    for k in sel.keys():
        if isinstance(k, str) and k.lower().startswith("commandline|contains"):
            cl_key = k
            break

    if not cl_key:
        return []

    val = sel.get(cl_key)
    values: List[str] = []
    if isinstance(val, list):
        values = [str(x) for x in val]
    elif isinstance(val, str):
        values = [val]
    else:
        return []

    # 안전한 regex 패턴 생성
    pat = "|".join(re.escape(v) for v in values if v)
    if not pat:
        return []

    return [
        Rule(
            id=rid,
            name=title,
            description="Auto-converted from Sigma-like selection contains",
            field="command_line",
            pattern=pat,
            mitre_technique=mitre,
            severity="medium",
            operator="contains",
        )
    ]


def normalize_severity(v: Any) -> str:
    """
    심각도 값을 정규화

    Args:
        v: 심각도 값 (문자열 또는 기타)

    Returns:
        정규화된 심각도 ("low", "medium", "high", "critical")
    """
    s = str(v).lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    return "medium"


def load_rules(rules_dir: Path) -> List[Rule]:
    """
    규칙 디렉토리에서 YAML 규칙 파일을 로드

    지원 형식:
    1. 네이티브 BreachScope 규칙 스키마
    2. Sigma-like 규칙 (최소 지원)

    Args:
        rules_dir: 규칙 파일이 있는 디렉토리

    Returns:
        로드된 Rule 리스트
    """
    rules: List[Rule] = []

    # YAML 파일 로드 (.yml, .yaml)
    for ext in ("*.yml", "*.yaml"):
        for p in sorted(rules_dir.rglob(ext)):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue

            # 단일 규칙 또는 리스트로 처리
            if isinstance(data, dict):
                data = [data]

            for r in data or []:
                # 네이티브 스키마
                if isinstance(r, dict) and (
                    ("id" in r and "name" in r and "pattern" in r)
                ):
                    try:
                        op: Optional[str] = r.get("operator")
                        fields_val = r.get("fields")
                        fields_list: Optional[List[str]] = None

                        if isinstance(fields_val, list):
                            fields_list = [str(x) for x in fields_val]
                        elif isinstance(fields_val, str):
                            fields_list = [s.strip() for s in fields_val.split(",") if s.strip()]

                        rules.append(
                            Rule(
                                id=str(r["id"]),
                                name=str(r["name"]),
                                description=str(r.get("description", "")),
                                field=str(r.get("field", "command_line")),
                                pattern=str(r["pattern"]),
                                mitre_technique=r.get("mitre_technique"),
                                severity=normalize_severity(r.get("severity", "medium")),
                                operator=(str(op).lower() if op else None),
                                fields=fields_list,
                            )
                        )
                    except Exception:
                        pass
                    continue

                # Sigma-like 최소 지원
                if isinstance(r, dict) and ("detection" in r or "title" in r):
                    try:
                        rules.extend(sigma_like_to_rules(r))
                    except Exception:
                        pass

    # 규칙이 없으면 기본 규칙 반환
    if rules:
        return rules

    return _get_default_rules()


def _get_default_rules() -> List[Rule]:
    """
    기본 규칙 반환 (규칙 파일이 없을 때)

    Returns:
        기본 Rule 리스트
    """
    return [
        Rule(
            id="R-ENC",
            name="Encoded PowerShell Command",
            description="Powershell with -enc or -encodedcommand",
            field="command_line",
            pattern=r"powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
            mitre_technique="T1059.001",
            severity="medium",
            operator="regex",
        ),
        Rule(
            id="R-DL",
            name="Suspicious Web Download",
            description="Script using web client/request (generic)",
            field="command_line",
            pattern=r"(webrequest|wget|curl|net\.webclient)",
            mitre_technique="T1105",
            severity="medium",
            operator="regex",
        ),
    ]


def validate_rule(rule: Rule) -> bool:
    """
    규칙 유효성 검증

    Args:
        rule: 검증할 Rule 객체

    Returns:
        유효성 여부
    """
    if not rule.id or not rule.name or not rule.pattern:
        return False

    # operator가 regex인 경우 패턴 컴파일 테스트
    if rule.operator == "regex" or (not rule.operator and not rule.pattern.startswith(("contains:", "startswith:", "endswith:", "equals:"))):
        try:
            re.compile(rule.pattern)
        except re.error:
            return False

    return True
