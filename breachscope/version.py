"""Single-source version resolution for BreachScope."""
from __future__ import annotations

import os
from importlib.metadata import PackageNotFoundError, version as distribution_version
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 fallback
    import tomli as tomllib


def get_project_version(repo_root: str | Path | None = None) -> str:
    """Return the package SemVer from source metadata or the installed distribution."""
    root = Path(repo_root).resolve() if repo_root is not None else Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    try:
        with pyproject.open("rb") as fh:
            project = tomllib.load(fh).get("project", {})
        value = str(project.get("version") or "").strip()
        if value:
            return value
    except (OSError, tomllib.TOMLDecodeError):
        pass

    try:
        return distribution_version("breachscope")
    except PackageNotFoundError:
        return "0.0.0"


def get_build_version(repo_root: str | Path | None = None) -> str:
    """Return an optional build label, falling back to the package SemVer."""
    override = os.getenv("BS_BUILD_VERSION", "").strip()
    return override or get_project_version(repo_root)


__version__ = get_project_version()

__all__ = ["__version__", "get_build_version", "get_project_version"]
