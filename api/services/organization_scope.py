"""Organization scope helpers for request/session/case isolation."""
from __future__ import annotations

import os
import re
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
