from __future__ import annotations

from copy import deepcopy
import ntpath
from typing import Any


# BREACHSCOPE_P2_11D_EVENT_FIELD_COMPARISON_V1
_INTERNAL_FIELDREF_PREFIX = "__breachscope_fieldref__:"
_INTERNAL_BASENAME_NE_FIELDREF_PREFIX = "__breachscope_basename_ne_fieldref__:"


def rewrite_field_compare_conditions(mapping: Any) -> Any:
    """Desugar supported all_of-only field comparisons to internal sentinels."""
    all_of = mapping.get("all_of") if isinstance(mapping, dict) else None
    supported = {"equals_field", "basename_not_equals_field"}
    if not isinstance(all_of, list) or not any(
        isinstance(condition, dict)
        and str(condition.get("operator") or "equals").lower() in supported
        for condition in all_of
    ):
        return mapping

    raw = deepcopy(mapping)
    for condition in raw.get("all_of", []):
        if not isinstance(condition, dict):
            continue
        operator = str(condition.get("operator") or "equals").lower()
        if operator not in supported:
            continue
        referenced_field = str(
            condition.get("pattern") if "pattern" in condition else ""
        ).strip()
        if not referenced_field:
            continue
        condition["operator"] = "equals"
        prefix = (
            _INTERNAL_FIELDREF_PREFIX
            if operator == "equals_field"
            else _INTERNAL_BASENAME_NE_FIELDREF_PREFIX
        )
        condition["pattern"] = prefix + referenced_field
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
    if operator != "equals":
        return None

    mode = ""
    if pattern.startswith(_INTERNAL_FIELDREF_PREFIX):
        mode = "equals"
        right_field = pattern[len(_INTERNAL_FIELDREF_PREFIX):].strip()
    elif pattern.startswith(_INTERNAL_BASENAME_NE_FIELDREF_PREFIX):
        mode = "basename_not_equals"
        right_field = pattern[len(_INTERNAL_BASENAME_NE_FIELDREF_PREFIX):].strip()
    else:
        return None

    left_field = str(condition.get("field") or "").strip()
    if not left_field or not right_field:
        return False
    left_value = field_text(event, left_field)
    right_value = field_text(event, right_field)
    if not left_value or not right_value:
        return False

    if mode == "basename_not_equals":
        left_name = ntpath.basename(left_value.strip()).casefold()
        right_name = ntpath.basename(right_value.strip()).casefold()
        if not left_name or not right_name:
            return False
        return left_name != right_name

    return _field_values_equal(
        left_value, right_value, left_field=left_field, right_field=right_field
    )
