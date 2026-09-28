"""Organization scope helpers for request/session/case isolation."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Mapping

DEFAULT_ORGANIZATION_ID = "default"
ORGANIZATION_HEADER = "x-breachscope-organization"
MAX_ORGANIZATION_ID_LENGTH = 64
_ORGANIZATION_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class OrganizationScopeError(ValueError):
    """Raised when an organization identifier is unsafe or ambiguous."""


def normalize_organization_id(
    value: object | None,
    *,
    default: str | None = DEFAULT_ORGANIZATION_ID,
) -> str:
    candidate = str(value or "").strip().casefold()
    if not candidate:
        if default is None:
            raise OrganizationScopeError("organization_id is required")
        candidate = str(default).strip().casefold()
    if (
        len(candidate) > MAX_ORGANIZATION_ID_LENGTH
        or not _ORGANIZATION_RE.fullmatch(candidate)
    ):
        raise OrganizationScopeError(
            "organization_id must match [a-z0-9][a-z0-9._-]{0,63}"
        )
    return candidate


def configured_default_organization(
    env: Mapping[str, str] | None = None,
) -> str:
    source = os.environ if env is None else env
    return normalize_organization_id(
        source.get("BS_DEFAULT_ORGANIZATION_ID", DEFAULT_ORGANIZATION_ID)
    )


def row_organization_id(
    row: Mapping[str, object],
    *,
    default: str | None = None,
) -> str:
    """Resolve stored organization, treating legacy rows as the deployment default."""
    fallback = configured_default_organization() if default is None else default
    return normalize_organization_id(row.get("organization_id"), default=fallback)


def organization_scoped_file_root(
    base_path: Path,
    *,
    namespace: str,
) -> Path:
    base = Path(base_path).expanduser().resolve()
    safe_namespace = str(namespace or "").strip().replace("-", "_")
    if not safe_namespace or not re.fullmatch(r"[a-z0-9_]+", safe_namespace):
        raise OrganizationScopeError("organization storage namespace is invalid")
    return base.parent / f"{safe_namespace}_organizations"


def organization_scoped_file_path(
    base_path: Path,
    organization_id: str | None,
    *,
    namespace: str,
) -> Path:
    base = Path(base_path).expanduser().resolve()
    organization = normalize_organization_id(
        organization_id,
        default=configured_default_organization(),
    )
    if organization == configured_default_organization():
        return base
    expected_root_name = f"{str(namespace or '').strip().replace('-', '_')}_organizations"
    if (
        base.parent.name == organization
        and base.parent.parent.name == expected_root_name
    ):
        return base
    return organization_scoped_file_root(
        base,
        namespace=namespace,
    ) / organization / base.name


def organization_scoped_root(
    base_root: Path,
    organization_id: str | None,
) -> Path:
    base = Path(base_root).expanduser().resolve()
    organization = normalize_organization_id(
        organization_id,
        default=configured_default_organization(),
    )
    if organization == configured_default_organization():
        return base
    if base.name == organization and base.parent.name == "organizations":
        return base
    return base / "organizations" / organization
