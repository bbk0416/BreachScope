"""Central work-directory trust boundary for the web/API surface."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


class WorkDirBoundaryError(ValueError):
    """A path is outside BreachScope-managed work-directory roots."""


def cases_root() -> Path:
    raw = os.getenv("BS_CASES_ROOT")
    root = Path(raw).expanduser() if raw else Path.home() / ".breachscope" / "cases"
    return root.resolve()


def temp_root() -> Path:
    return Path(tempfile.gettempdir()).resolve()


def _strict_descendant(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    return relative != Path(".")


def _is_managed_temp(path: Path) -> bool:
    root = temp_root()
    # Legacy BS_USE_SYSTEM_TEMP uses tempfile.mkdtemp(prefix="bs_web_"), which
    # creates a DIRECT child of the OS temp root. Requiring direct parenthood
    # avoids accepting attacker-controlled nested temp paths by basename alone.
    return path.parent == root and path.name.startswith("bs_web_")


def validate_managed_work_dir(
    path: str | Path,
    *,
    allow_temp: bool = True,
    must_exist: bool = False,
) -> Path:
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise WorkDirBoundaryError(f"Unable to resolve work_dir: {candidate}") from exc

    root = cases_root()
    allowed = _strict_descendant(resolved, root)
    if not allowed and allow_temp:
        allowed = _is_managed_temp(resolved)

    if not allowed:
        raise WorkDirBoundaryError(
            f"work_dir is outside BreachScope managed roots: {resolved}"
        )

    if must_exist and (not resolved.exists() or not resolved.is_dir()):
        raise FileNotFoundError(f"Managed work_dir does not exist: {resolved}")

    return resolved


def resolve_user_work_dir(path: str | Path, *, create: bool = True) -> Path:
    raw = str(path).strip()
    if not raw:
        raise WorkDirBoundaryError("work_dir cannot be empty")

    requested = Path(raw).expanduser()
    root = cases_root()
    candidate = requested if requested.is_absolute() else root / requested

    resolved = validate_managed_work_dir(
        candidate,
        allow_temp=False,
        must_exist=False,
    )

    if create:
        resolved.mkdir(parents=True, exist_ok=True)

    if not resolved.is_dir():
        raise WorkDirBoundaryError(f"work_dir is not a directory: {resolved}")

    probe = resolved / ".breachscope_write_probe"
    try:
        probe.write_text("test", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise WorkDirBoundaryError(f"work_dir is not writable: {resolved}") from exc

    return resolved


def is_safe_managed_delete(path: str | Path) -> bool:
    try:
        resolved = validate_managed_work_dir(
            path,
            allow_temp=True,
            must_exist=True,
        )
    except (WorkDirBoundaryError, FileNotFoundError, OSError):
        return False
    return resolved.is_dir()
