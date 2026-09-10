from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any

from .schemas import Rule


_INTERNAL_FIELDREF_PREFIX = "__breachscope_fieldref__:"
_INSTALL_MARKER = "_breachscope_p2_11d_field_compare_installed"


def _normalized_host_aliases(value: Any) -> set[str]:
    text = str(value or "").strip().rstrip(".").casefold()
    if not text:
        return set()
    aliases = {text}
    if "." in text:
        aliases.add(text.split(".", 1)[0])
    return aliases


def _field_values_equal(
    left: str,
    right: str,
    *,
    left_field: str,
    right_field: str,
) -> bool:
    if left_field.casefold() == "host" or right_field.casefold() == "host":
        return bool(
            _normalized_host_aliases(left)
            & _normalized_host_aliases(right)
        )
    return left.strip().casefold() == right.strip().casefold()


def install(rules_module, analyzer_module) -> None:
    """Install all_of-only event-field comparison support.

    YAML syntax:
        - field: TargetDomainName
          operator: equals_field
          pattern: host

    `equals_field` is deliberately not a top-level native operator. The loader
    rewrites it to an internal equals sentinel, and the analyzer resolves the
    referenced field at evaluation time. Missing fields fail closed.
    """
    if getattr(analyzer_module, _INSTALL_MARKER, False):
        return

    original_loader = rules_module._native_rule_from_mapping
    original_all_of = analyzer_module._rule_all_of_matches

    def load_native_rule(mapping, path, index):
        raw = mapping
        all_of = mapping.get("all_of") if isinstance(mapping, dict) else None
        if isinstance(all_of, list) and any(
            isinstance(condition, dict)
            and str(condition.get("operator") or "equals").lower() == "equals_field"
            for condition in all_of
        ):
            raw = deepcopy(mapping)
            for condition in raw.get("all_of", []):
                if not isinstance(condition, dict):
                    continue
                operator = str(condition.get("operator") or "equals").lower()
                if operator != "equals_field":
                    continue
                referenced_field = str(
                    condition.get("pattern")
                    if "pattern" in condition
                    else ""
                ).strip()
                if not referenced_field:
                    continue
                condition["operator"] = "equals"
                condition["pattern"] = (
                    _INTERNAL_FIELDREF_PREFIX + referenced_field
                )
        return original_loader(raw, path, index)

    def rule_all_of_matches(event, rule: Rule) -> bool:
        conditions = getattr(rule, "all_of", None)
        if not conditions:
            return True

        literal_conditions = []
        found_fieldref = False

        for condition in conditions:
            if not isinstance(condition, dict):
                literal_conditions.append(condition)
                continue

            operator = str(condition.get("operator") or "equals").lower()
            pattern = str(
                condition.get("pattern")
                if "pattern" in condition
                else ""
            )
            if (
                operator == "equals"
                and pattern.startswith(_INTERNAL_FIELDREF_PREFIX)
            ):
                found_fieldref = True
                left_field = str(condition.get("field") or "").strip()
                right_field = pattern[len(_INTERNAL_FIELDREF_PREFIX):].strip()
                if not left_field or not right_field:
                    return False

                left_value = analyzer_module._event_field_text(
                    event, left_field
                )
                right_value = analyzer_module._event_field_text(
                    event, right_field
                )
                if not left_value or not right_value:
                    return False

                if not _field_values_equal(
                    left_value,
                    right_value,
                    left_field=left_field,
                    right_field=right_field,
                ):
                    return False
                continue

            literal_conditions.append(condition)

        if not found_fieldref:
            return original_all_of(event, rule)
        if not literal_conditions:
            return True
        return original_all_of(
            event,
            replace(rule, all_of=literal_conditions),
        )

    rules_module._native_rule_from_mapping = load_native_rule
    analyzer_module._rule_all_of_matches = rule_all_of_matches
    setattr(analyzer_module, _INSTALL_MARKER, True)
