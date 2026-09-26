"""Small optional RBAC layer for rule lifecycle operations."""
from __future__ import annotations

import os
from dataclasses import dataclass

from fastapi import HTTPException, Request

from api.security import (
    SESSION_COOKIE_NAME,
    auth_is_enabled,
    request_is_authenticated,
    verify_session_token,
)


ROLE_ADMIN = "admin"
ROLE_AUTHOR = "author"
ROLE_REVIEWER = "reviewer"
ROLE_OPERATOR = "operator"
KNOWN_ROLES = {ROLE_ADMIN, ROLE_AUTHOR, ROLE_REVIEWER, ROLE_OPERATOR}
ROLE_PASSWORD_ENV = {
    ROLE_AUTHOR: "BS_AUTHOR_PASSWORD",
    ROLE_REVIEWER: "BS_REVIEWER_PASSWORD",
    ROLE_OPERATOR: "BS_OPERATOR_PASSWORD",
}


@dataclass(frozen=True)
class RequestIdentity:
    subject: str
    role: str
    method: str


def configured_rbac_roles() -> list[str]:
    return [
        role
        for role, env_name in ROLE_PASSWORD_ENV.items()
        if os.getenv(env_name, "").strip()
    ]


def rbac_is_enabled() -> bool:
    return bool(configured_rbac_roles())


def identity_from_request(request: Request) -> RequestIdentity:
    authenticated, method = request_is_authenticated(request)

    if method == "session" and authenticated:
        payload = verify_session_token(
            request.cookies.get(SESSION_COOKIE_NAME)
        ) or {}
        subject = str(payload.get("sub") or ROLE_ADMIN)
        role = str(payload.get("role") or subject).strip().lower()
        if role not in KNOWN_ROLES:
            role = "none"
        return RequestIdentity(subject=subject, role=role, method=method)

    if method == "api_key" and authenticated:
        return RequestIdentity(
            subject="api_key",
            role=ROLE_ADMIN,
            method=method,
        )

    if not auth_is_enabled():
        return RequestIdentity(
            subject="local-demo",
            role=ROLE_ADMIN,
            method="none",
        )

    return RequestIdentity(
        subject="unauthenticated",
        role="none",
        method="none",
    )


def require_roles(request: Request, *allowed_roles: str) -> RequestIdentity:
    identity = identity_from_request(request)

    # Backward compatibility: deployments that do not configure role accounts
    # retain the existing single-admin behavior.
    if not rbac_is_enabled():
        return RequestIdentity(
            subject=identity.subject,
            role=ROLE_ADMIN,
            method=identity.method,
        )

    if identity.role == ROLE_ADMIN or identity.role in set(allowed_roles):
        return identity

    required = ", ".join(sorted(set(allowed_roles)))
    raise HTTPException(
        status_code=403,
        detail=(
            f"RBAC role '{identity.role}' is not allowed for this operation. "
            f"Required role: {required} or admin."
        ),
    )
