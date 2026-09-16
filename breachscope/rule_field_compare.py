from __future__ import annotations

from copy import deepcopy
from typing import Any


# BREACHSCOPE_P2_11D_EVENT_FIELD_COMPARISON_V1
_INTERNAL_FIELDREF_PREFIX = "__breachscope_fieldref__:"


def rewrite_field_compare_conditions(mapping: Any) -> Any:
    """Desugar all_of-only equals_field conditions to an internal sentinel."""
    all_of = mapping.get("all_of") if isinstance(mapping, dict) else None
    if not isinstance(all_of, list) or not any(
        isinstance(condition, dict)
        and str(condition.get("operator") or "equals").lower() == "equals_field"
        for condition in all_of
    ):
        return mapping

    raw = deepcopy(mapping)
    for condition in raw.get("all_of", []):
        if not isinstance(condition, dict):
            continue
        operator = str(condition.get("operator") or "equals").lower()
        if operator != "equals_field":
            continue
        referenced_field = str(
            condition.get("pattern") if "pattern" in condition else ""
        ).strip()
        if not referenced_field:
            continue
        condition["operator"] = "equals"
        condition["pattern"] = _INTERNAL_FIELDREF_PREFIX + referenced_field
    return raw


def _normalized_host_aliases(value: Any) -> set[str]:
    text = str(value or "").strip().rstrip(".").casefold()
    if not text:
        return set()
    aliases = {text}
    if "." in text:
        aliases.add(text.split(".", 1)[0])
    return aliases


def _field_values_equal(left: str, right: str, *, left_field: str, right_field: str) -> bool:
    if left_field.casefold() == "host" or right_field.casefold() == "host":
        return bool(_normalized_host_aliases(left) & _normalized_host_aliases(right))
    return left.strip().casefold() == right.strip().casefold()


def match_field_reference_condition(event, condition: Any, field_text) -> bool | None:
    """Return None for a literal condition, otherwise the field-compare result."""
    if not isinstance(condition, dict):
        return None
    operator = str(condition.get("operator") or "equals").lower()
    pattern = str(condition.get("pattern") if "pattern" in condition else "")
    if operator != "equals" or not pattern.startswith(_INTERNAL_FIELDREF_PREFIX):
        return None

    left_field = str(condition.get("field") or "").strip()
    right_field = pattern[len(_INTERNAL_FIELDREF_PREFIX):].strip()
    if not left_field or not right_field:
        return False
    left_value = field_text(event, left_field)
    right_value = field_text(event, right_field)
    if not left_value or not right_value:
        return False
    return _field_values_equal(
        left_value, right_value, left_field=left_field, right_field=right_field
    )
