"""Fail-closed case-history index integrity guard."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .case_history import CaseHistoryService


class CaseHistoryIndexCorruptionError(RuntimeError):
    """The case-history index is corrupt and could not be safely quarantined."""


def _empty_index() -> Dict[str, Any]:
    return {"version": 1, "cases": []}


def _next_quarantine_path(index_path: Path) -> Path:
    base = index_path.with_suffix(index_path.suffix + ".broken")
    if not base.exists():
        return base

    suffix = 2
    while True:
        candidate = index_path.with_suffix(index_path.suffix + f".broken.{suffix}")
        if not candidate.exists():
            return candidate
        suffix += 1


def _quarantine_corrupt_index(index_path: Path) -> Path:
    broken = _next_quarantine_path(index_path)
    try:
        index_path.replace(broken)
    except OSError as exc:
        raise CaseHistoryIndexCorruptionError(
            f"Corrupt case-history index could not be quarantined: {index_path}"
        ) from exc
    return broken


def _is_valid_index_shape(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if "cases" not in data:
        return True
    cases = data.get("cases")
    if not isinstance(cases, list):
        return False
    return all(isinstance(row, dict) for row in cases)


def _read_index_fail_closed(self: CaseHistoryService) -> Dict[str, Any]:
    if not self.index_path.exists():
        return _empty_index()

    try:
        data = json.loads(self.index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        _quarantine_corrupt_index(self.index_path)
        return _empty_index()

    if not _is_valid_index_shape(data):
        _quarantine_corrupt_index(self.index_path)
        return _empty_index()

    data.setdefault("version", 1)
    data.setdefault("cases", [])
    return data


def install() -> None:
    CaseHistoryService._read_index = _read_index_fail_closed


install()

# BREACHSCOPE_P2_08K_CORRUPT_CASE_INDEX_FAIL_CLOSED_V1
