"""Strict pySigma validation and lossless BreachScope subset conversion."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from .schemas import Rule


class SigmaIntegrationError(ValueError):
    """Raised when a Sigma rule cannot be represented safely by BreachScope."""


def _require_pysigma():
    try:
        from sigma.collection import SigmaCollection
    except Exception as exc:
        raise RuntimeError(
            "pySigma is required for Sigma rules. Install project dependencies "
            "(pysigma>=1.5,<2)."
        ) from exc
    return SigmaCollection


def validate_with_pysigma(doc: Dict[str, Any]) -> None:
    """Parse a single rule with the real pySigma parser.

    BreachScope intentionally performs pySigma syntax/model validation before
    applying its narrower execution subset.
    """
    SigmaCollection = _require_pysigma()
    text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    try:
        SigmaCollection.from_yaml(text)
    except Exception as exc:
        raise SigmaIntegrationError(f"pySigma rejected Sigma rule: {exc}") from exc


def _attack_tag(tags: Any) -> str | None:
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if not isinstance(tag, str):
            continue
        lowered = tag.casefold()
        if lowered.startswith("attack.t"):
            return tag.split("attack.", 1)[-1].upper()
    return None


def _severity(value: Any) -> str:
    lowered = str(value or "medium").strip().casefold()
    if lowered in {"informational", "info", "low"}:
        return "low"
    if lowered == "medium":
        return "medium"
    if lowered == "high":
        return "high"
    if lowered in {"critical", "fatal"}:
        return "critical"
    return "medium"


def _condition_selection(detection: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise SigmaIntegrationError("Sigma detection.condition must be a non-empty string")

    condition = condition.strip()
    # BreachScope Rule is a single-field predicate. Boolean Sigma conditions,
    # wildcard selection groups and thresholds cannot be represented without
    # changing semantics, so P0-09 rejects them rather than flattening them.
    forbidden = (
        " and ", " or ", " not ", " of ", "all of", "1 of",
        "them", "*", "(", ")",
    )
    lowered = f" {condition.casefold()} "
    if any(token in lowered for token in forbidden):
        raise SigmaIntegrationError(
            f"Unsupported Sigma condition for BreachScope subset: {condition!r}"
        )

    selection = detection.get(condition)
    if not isinstance(selection, dict) or not selection:
        raise SigmaIntegrationError(
            f"Sigma condition must name one mapping selection; got {condition!r}"
        )

    semantic_keys = [
        key for key in detection.keys()
        if key not in {"condition", "timeframe"} and isinstance(key, str)
    ]
    if semantic_keys != [condition] and set(semantic_keys) != {condition}:
        raise SigmaIntegrationError(
            "BreachScope subset requires exactly one referenced selection and "
            "no extra filter/selection blocks"
        )

    return condition, selection


def convert_supported_sigma_document(doc: Dict[str, Any]) -> List[Rule]:
    """Validate with pySigma, then convert only a lossless execution subset.

    Supported P0-09 subset:
      detection:
        <selection-name>:
          CommandLine|contains: <string or list[string]>
        condition: <selection-name>

    A value list is Sigma OR semantics and maps to the analyzer's existing
    pipe-separated contains targets. Multi-field selections, boolean
    conditions and other modifiers are rejected fail-closed.
    """
    if not isinstance(doc, dict):
        raise SigmaIntegrationError("Sigma document must be a mapping")
    if "detection" not in doc:
        raise SigmaIntegrationError("Sigma document has no detection block")

    validate_with_pysigma(doc)

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaIntegrationError("Sigma detection must be a mapping")

    _selection_name, selection = _condition_selection(detection)
    if len(selection) != 1:
        raise SigmaIntegrationError(
            "BreachScope subset cannot preserve multi-field Sigma AND semantics"
        )

    field_expr, raw_values = next(iter(selection.items()))
    if not isinstance(field_expr, str):
        raise SigmaIntegrationError("Sigma field expression must be a string")

    parts = field_expr.split("|")
    base_field = parts[0].strip().casefold()
    modifiers = [part.strip().casefold() for part in parts[1:] if part.strip()]

    if base_field != "commandline":
        raise SigmaIntegrationError(
            f"Unsupported Sigma field for P0-09 subset: {parts[0]!r}"
        )
    if modifiers != ["contains"]:
        raise SigmaIntegrationError(
            f"Unsupported Sigma modifier set for CommandLine: {modifiers!r}"
        )

    if isinstance(raw_values, str):
        values = [raw_values]
    elif isinstance(raw_values, list) and all(isinstance(v, str) for v in raw_values):
        values = list(raw_values)
    else:
        raise SigmaIntegrationError(
            "CommandLine|contains must be a string or list of strings"
        )

    values = [value for value in values if value]
    if not values:
        raise SigmaIntegrationError("CommandLine|contains cannot be empty")
    if any("|" in value for value in values):
        raise SigmaIntegrationError(
            "Literal '|' in Sigma contains value is unsupported because "
            "BreachScope uses '|' as its OR-target separator"
        )

    title = str(doc.get("title") or "Sigma Rule")
    rule_id = str(doc.get("id") or title)

    return [
        Rule(
            id=rule_id,
            name=title,
            description="Validated by pySigma; converted from strict CommandLine|contains subset",
            field="command_line",
            pattern="|".join(values),
            mitre_technique=_attack_tag(doc.get("tags")),
            severity=_severity(doc.get("level")),
            operator="contains",
        )
    ]


def iter_sigma_documents(rules_dir: Path) -> Iterable[tuple[Path, Dict[str, Any]]]:
    """Yield YAML documents that are actually Sigma detection rules."""
    for path in sorted(Path(rules_dir).glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        for index, doc in enumerate(yaml.safe_load_all(text), start=1):
            if isinstance(doc, dict) and "detection" in doc:
                yield path, doc


def preflight_sigma_rules(rules_dir: Path) -> None:
    """Fail closed before the legacy loader can silently swallow Sigma errors."""
    for path, doc in iter_sigma_documents(Path(rules_dir)):
        try:
            convert_supported_sigma_document(doc)
        except Exception as exc:
            raise SigmaIntegrationError(f"{path.name}: {exc}") from exc
