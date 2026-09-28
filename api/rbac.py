"""Small optional RBAC layer for rule lifecycle operations."""
from __future__ import annotations

import os
from dataclasses import dataclass

from fastapi import HTTPException, Request

from api.services.oidc_auth import configured_oidc_roles
from api.services.organization_scope import (
    configured_default_organization,
    normalize_organization_id,
)

from api.security import (
    SESSION_COOKIE_NAME,
    ApiKeyConfigurationError,
    ApiKeyOrganizationAccessError,
    ApiKeyOrganizationSelectorError,
    auth_is_enabled,
    extract_api_key,
    request_is_authenticated,
    resolve_api_key_credential,
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
    organization_id: str


def configured_rbac_roles() -> list[str]:
    roles = {
        role
        for role, env_name in ROLE_PASSWORD_ENV.items()
        if os.getenv(env_name, "").strip()
    }
    roles.update(role for role in configured_oidc_roles() if role != ROLE_ADMIN)
    return sorted(roles)


def rbac_is_enabled() -> bool:
    return bool(configured_rbac_roles())


def identity_from_request(request: Request) -> RequestIdentity:
    if extract_api_key(request):
        try:
            credential = resolve_api_key_credential(request)
        except ApiKeyOrganizationSelectorError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ApiKeyOrganizationAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ApiKeyConfigurationError as exc:
            raise HTTPException(
                status_code=503,
                detail="API-key delegation configuration is invalid.",
            ) from exc
        if credential is not None:
            return RequestIdentity(
                subject="api_key",
                role=ROLE_ADMIN,
                method="api_key",
                organization_id=credential.organization_id,
            )

    authenticated, method = request_is_authenticated(request)

    if method == "session" and authenticated:
        payload = verify_session_token(
            request.cookies.get(SESSION_COOKIE_NAME)
        ) or {}
        subject = str(payload.get("sub") or ROLE_ADMIN)
        role = str(payload.get("role") or subject).strip().lower()
        if role not in KNOWN_ROLES:
            role = "none"
        organization_id = normalize_organization_id(
            payload.get("org"),
            default=configured_default_organization(),
        )
        return RequestIdentity(
            subject=subject,
            role=role,
            method=method,
            organization_id=organization_id,
        )

    if not auth_is_enabled():
        return RequestIdentity(
            subject="local-demo",
            role=ROLE_ADMIN,
            method="none",
            organization_id=configured_default_organization(),
        )

    return RequestIdentity(
        subject="unauthenticated",
        role="none",
        method="none",
        organization_id=configured_default_organization(),
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
            organization_id=identity.organization_id,
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
