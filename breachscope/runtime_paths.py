"""Resolve runtime data from a source checkout or an installed wheel."""
from __future__ import annotations

from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parent
_SOURCE_ROOT = _PACKAGE_ROOT.parent
_PACKAGED_ROOT = _PACKAGE_ROOT / "runtime_data"
_SOURCE_CHECKOUT = (_SOURCE_ROOT / "pyproject.toml").is_file()


def _resolve_runtime_dir(name: str) -> Path:
    source = _SOURCE_ROOT / name
    if _SOURCE_CHECKOUT and source.is_dir():
        return source
    packaged = _PACKAGED_ROOT / name
    if packaged.is_dir():
        return packaged
    return source


def default_rules_dir() -> Path:
    return _resolve_runtime_dir("rules")


def default_templates_dir() -> Path:
    return _resolve_runtime_dir("templates")


def resolve_rules_dir(value: str | Path) -> Path:
    path = Path(value)
    if str(value) == "rules" and not path.exists():
        return default_rules_dir()
    return path


__all__ = ["default_rules_dir", "default_templates_dir", "resolve_rules_dir"]
