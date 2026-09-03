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


def sigma_like_to_rules(doc):
    return _bs_p009_convert_sigma(doc)


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


def load_rules(rules_dir):
    _bs_p009_preflight_sigma(Path(rules_dir))

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

                        all_of_val = r.get("all_of")
                        all_of_list = None
                        if all_of_val is not None:
                            if not isinstance(all_of_val, list) or not all_of_val:
                                raise ValueError("all_of must be a non-empty list")
                            all_of_list = []
                            for condition in all_of_val:
                                if not isinstance(condition, dict):
                                    raise ValueError("all_of conditions must be mappings")
                                condition_field = str(condition.get("field") or "").strip()
                                condition_pattern = str(condition.get("pattern") if "pattern" in condition else "")
                                condition_operator = str(condition.get("operator") or "equals").lower()
                                if not condition_field or condition_pattern == "":
                                    raise ValueError("all_of conditions require field and pattern")
                                if condition_operator not in {"regex", "contains", "startswith", "endswith", "equals"}:
                                    raise ValueError("unsupported all_of operator")
                                all_of_list.append({"field": condition_field, "operator": condition_operator, "pattern": condition_pattern})

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
                                all_of=all_of_list,
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

# BREACHSCOPE_P0_09_PYSIGMA_STRICT_V1
# Sigma rules are validated by the real pySigma parser, then accepted only if
# BreachScope can preserve their semantics losslessly in its current Rule model.
# Unsupported Sigma fails closed before the legacy loader's broad exception
# handler can silently discard the rule.
from .sigma_adapter import (
    convert_supported_sigma_document as _bs_p009_convert_sigma,
    preflight_sigma_rules as _bs_p009_preflight_sigma,
)
