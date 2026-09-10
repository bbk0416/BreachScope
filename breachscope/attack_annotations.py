"""ATT&CK mapping helpers shared by rule metadata and external evaluation."""
from __future__ import annotations

import re
from typing import Any


_ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

# Secondary mappings must describe the same observed behavior, not duplicate a
# detector merely to satisfy an evaluation corpus. R-ENC keeps PowerShell
# execution (T1059.001) as its primary mapping and also records Command
# Obfuscation (T1027.010) for the encoded-command behavior.
_SECONDARY_RULE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "R-ENC": ("T1027.010",),
}


def _normalize_technique(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if _ATTACK_ID_RE.fullmatch(text) else ""


def rule_techniques(rule_id: str, primary: Any) -> list[str]:
    """Return ordered, de-duplicated ATT&CK mappings for one rule."""
    values: list[str] = []
    first = _normalize_technique(primary)
    if first:
        values.append(first)
    for item in _SECONDARY_RULE_TECHNIQUES.get(str(rule_id), ()):
        normalized = _normalize_technique(item)
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def attack_requirement_satisfied(required: Any, observed: Any) -> bool:
    """Match exact IDs, or a parent requirement to an observed sub-technique."""
    required_id = _normalize_technique(required)
    observed_id = _normalize_technique(observed)
    if not required_id or not observed_id:
        return False
    if required_id == observed_id:
        return True
    if "." not in required_id and observed_id.startswith(required_id + "."):
        return True
    return False
