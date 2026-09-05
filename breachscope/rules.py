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


# BREACHSCOPE_P2_06C_NATIVE_RULE_FAIL_CLOSED_V2
class RuleLoadError(ValueError):
    pass


_NATIVE_OPERATORS = {"regex", "contains", "startswith", "endswith", "equals"}


def _native_rule_from_mapping(r: Dict[str, Any], path: Path, index: int) -> Rule:
    location = f"{path.name}[{index}]"

    missing = [key for key in ("id", "name", "pattern") if key not in r]
    if missing:
        raise RuleLoadError(
            f"{location}: native rule missing required field(s): {', '.join(missing)}"
        )

    rule_id = str(r.get("id") or "").strip()
    rule_name = str(r.get("name") or "").strip()
    pattern = str(r.get("pattern") if "pattern" in r else "")
    if not rule_id or not rule_name or pattern == "":
        raise RuleLoadError(f"{location}: native rule id/name/pattern must be non-empty")

    op: Optional[str] = r.get("operator")
    normalized_op = str(op).lower() if op else None
    if normalized_op and normalized_op not in _NATIVE_OPERATORS:
        raise RuleLoadError(f"{location}: unsupported native operator: {normalized_op}")

    fields_val = r.get("fields")
    fields_list: Optional[List[str]] = None
    if isinstance(fields_val, list):
        fields_list = [str(x) for x in fields_val]
    elif isinstance(fields_val, str):
        fields_list = [s.strip() for s in fields_val.split(",") if s.strip()]
    elif fields_val is not None:
        raise RuleLoadError(f"{location}: fields must be a string or list")

    all_of_val = r.get("all_of")
    all_of_list = None
    if all_of_val is not None:
        if not isinstance(all_of_val, list) or not all_of_val:
            raise RuleLoadError(f"{location}: all_of must be a non-empty list")

        all_of_list = []
        for condition_index, condition in enumerate(all_of_val, start=1):
            if not isinstance(condition, dict):
                raise RuleLoadError(
                    f"{location}: all_of[{condition_index}] must be a mapping"
                )

            condition_field = str(condition.get("field") or "").strip()
            condition_pattern = str(
                condition.get("pattern") if "pattern" in condition else ""
            )
            condition_operator = str(condition.get("operator") or "equals").lower()

            if not condition_field or condition_pattern == "":
                raise RuleLoadError(
                    f"{location}: all_of[{condition_index}] requires field and pattern"
                )

            if condition_operator not in _NATIVE_OPERATORS:
                raise RuleLoadError(
                    f"{location}: all_of[{condition_index}] unsupported operator: "
                    f"{condition_operator}"
                )

            if condition_operator == "regex":
                try:
                    re.compile(condition_pattern)
                except re.error as exc:
                    raise RuleLoadError(
                        f"{location}: all_of[{condition_index}] invalid regex: {exc}"
                    ) from exc

            all_of_list.append({
                "field": condition_field,
                "operator": condition_operator,
                "pattern": condition_pattern,
            })

    rule = Rule(
        id=rule_id,
        name=rule_name,
        description=str(r.get("description", "")),
        field=str(r.get("field", "command_line")),
        pattern=pattern,
        mitre_technique=r.get("mitre_technique"),
        severity=normalize_severity(r.get("severity", "medium")),
        operator=normalized_op,
        fields=fields_list,
        all_of=all_of_list,
    )

    if not validate_rule(rule):
        raise RuleLoadError(f"{location}: native rule failed validation")

    return rule


def load_rules(rules_dir):
    rules_dir = Path(rules_dir)
    _bs_p009_preflight_sigma(rules_dir)

    rules: List[Rule] = []
    yaml_files = sorted({
        path
        for pattern in ("*.yml", "*.yaml")
        for path in rules_dir.rglob(pattern)
    })

    for path in yaml_files:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuleLoadError(f"{path.name}: YAML parse failed: {exc}") from exc

        if data is None:
            raise RuleLoadError(f"{path.name}: rule file is empty")

        if isinstance(data, dict):
            documents = [data]
        elif isinstance(data, list):
            documents = data
        else:
            raise RuleLoadError(
                f"{path.name}: top-level YAML must be a rule mapping or list of mappings"
            )

        if not documents:
            raise RuleLoadError(f"{path.name}: rule file contains no rules")

        for index, document in enumerate(documents, start=1):
            if not isinstance(document, dict):
                raise RuleLoadError(
                    f"{path.name}[{index}]: rule entry must be a mapping"
                )

            if "detection" in document or "title" in document:
                rules.extend(sigma_like_to_rules(document))
                continue

            rules.append(_native_rule_from_mapping(document, path, index))

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
    if not rule.id or not rule.name or not rule.pattern:
        return False

    operator = (rule.operator or "").lower()
    if operator and operator not in _NATIVE_OPERATORS:
        return False

    if operator == "regex" or (
        not operator
        and not rule.pattern.startswith(
            ("contains:", "startswith:", "endswith:", "equals:")
        )
    ):
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
