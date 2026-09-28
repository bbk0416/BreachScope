"""Small optional RBAC layer for rule lifecycle operations."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Mapping

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

ORGANIZATION_RBAC_POLICIES_ENV = "BS_ORGANIZATION_RBAC_POLICIES"
PERMISSION_RULE_AUTHOR = "rule.author"
PERMISSION_RULE_REVIEW = "rule.review"
PERMISSION_RULE_OPERATE = "rule.operate"
PERMISSION_ANALYSIS_CUSTOM_RULES = "analysis.custom_rules"
PERMISSION_CASE_OBJECT_STORAGE = "case.object_storage"
KNOWN_PERMISSIONS = {
    PERMISSION_RULE_AUTHOR,
    PERMISSION_RULE_REVIEW,
    PERMISSION_RULE_OPERATE,
    PERMISSION_ANALYSIS_CUSTOM_RULES,
    PERMISSION_CASE_OBJECT_STORAGE,
}
DEFAULT_ROLE_PERMISSIONS = {
    ROLE_ADMIN: {"*"},
    ROLE_AUTHOR: {PERMISSION_RULE_AUTHOR},
    ROLE_REVIEWER: {PERMISSION_RULE_REVIEW},
    ROLE_OPERATOR: {
        PERMISSION_RULE_OPERATE,
        PERMISSION_ANALYSIS_CUSTOM_RULES,
        PERMISSION_CASE_OBJECT_STORAGE,
    },
}


class OrganizationRbacPolicyError(ValueError):
    """Raised when organization-specific RBAC policy is invalid."""


@dataclass(frozen=True)
class RequestIdentity:
    subject: str
    role: str
    method: str
    organization_id: str
    api_key_delegated: bool | None = None


def organization_rbac_policy_settings_present(
    env: Mapping[str, str] | None = None,
) -> bool:
    source = os.environ if env is None else env
    raw = str(source.get(ORGANIZATION_RBAC_POLICIES_ENV, "") or "").strip()
    if not raw:
        return False
    try:
        return bool(configured_organization_rbac_policies(source))
    except OrganizationRbacPolicyError:
        return True


def configured_organization_rbac_policies(
    env: Mapping[str, str] | None = None,
) -> dict[str, dict[str, frozenset[str]]]:
    """Parse partial per-organization role permission overrides."""
    source = os.environ if env is None else env
    raw = str(source.get(ORGANIZATION_RBAC_POLICIES_ENV, "") or "").strip()
    if not raw:
        return {}

    def _unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OrganizationRbacPolicyError(
                    "BS_ORGANIZATION_RBAC_POLICIES contains duplicate entries."
                )
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise OrganizationRbacPolicyError(
            "BS_ORGANIZATION_RBAC_POLICIES must be a JSON object."
        ) from exc
    if not isinstance(payload, dict):
        raise OrganizationRbacPolicyError(
            "BS_ORGANIZATION_RBAC_POLICIES must be a JSON object."
        )

    policies: dict[str, dict[str, frozenset[str]]] = {}
    for raw_org, raw_roles in payload.items():
        try:
            organization_id = normalize_organization_id(
                raw_org,
                default=None,
            )
        except ValueError as exc:
            raise OrganizationRbacPolicyError(
                "BS_ORGANIZATION_RBAC_POLICIES contains an invalid organization ID."
            ) from exc
        if organization_id in policies:
            raise OrganizationRbacPolicyError(
                "BS_ORGANIZATION_RBAC_POLICIES contains duplicate normalized organizations."
            )
        if not isinstance(raw_roles, dict):
            raise OrganizationRbacPolicyError(
                "Each organization RBAC policy must be a JSON object."
            )

        role_map: dict[str, frozenset[str]] = {}
        for raw_role, raw_permissions in raw_roles.items():
            role = str(raw_role or "").strip().lower()
            if role not in KNOWN_ROLES:
                raise OrganizationRbacPolicyError(
                    f"Unknown RBAC role in organization policy: {role or raw_role}"
                )
            if role in role_map:
                raise OrganizationRbacPolicyError(
                    "Organization RBAC policy contains duplicate normalized roles."
                )
            if not isinstance(raw_permissions, list):
                raise OrganizationRbacPolicyError(
                    f"Organization RBAC permissions for {role} must be a JSON array."
                )
            permissions: set[str] = set()
            for raw_permission in raw_permissions:
                permission = str(raw_permission or "").strip()
                if permission != "*" and permission not in KNOWN_PERMISSIONS:
                    raise OrganizationRbacPolicyError(
                        f"Unknown organization RBAC permission: {permission}"
                    )
                if not permission:
                    raise OrganizationRbacPolicyError(
                        "Organization RBAC permissions must not be empty."
                    )
                permissions.add(permission)
            role_map[role] = frozenset(permissions)
        policies[organization_id] = role_map
    return policies


def effective_role_permissions(
    organization_id: str,
    role: str,
    env: Mapping[str, str] | None = None,
) -> frozenset[str]:
    organization = normalize_organization_id(
        organization_id,
        default=configured_default_organization(),
    )
    normalized_role = str(role or "").strip().lower()
    defaults = frozenset(DEFAULT_ROLE_PERMISSIONS.get(normalized_role, set()))
    policies = configured_organization_rbac_policies(env)
    override = policies.get(organization, {}).get(normalized_role)
    return defaults if override is None else override


def configured_rbac_roles() -> list[str]:
    roles = {
        role
        for role, env_name in ROLE_PASSWORD_ENV.items()
        if os.getenv(env_name, "").strip()
    }
    roles.update(role for role in configured_oidc_roles() if role != ROLE_ADMIN)
    return sorted(roles)


def rbac_is_enabled() -> bool:
    return bool(
        configured_rbac_roles()
        or organization_rbac_policy_settings_present()
    )


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
                api_key_delegated=credential.delegated,
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


def require_roles(
    request: Request,
    *allowed_roles: str,
    permission: str | None = None,
) -> RequestIdentity:
    identity = identity_from_request(request)

    if permission is not None and permission not in KNOWN_PERMISSIONS:
        raise RuntimeError(f"Unknown RBAC permission requested: {permission}")

    # Local demos keep the historical single-admin behavior.
    if identity.method == "none" and not auth_is_enabled():
        return RequestIdentity(
            subject=identity.subject,
            role=ROLE_ADMIN,
            method=identity.method,
            organization_id=identity.organization_id,
            api_key_delegated=identity.api_key_delegated,
        )

    # The deployment-wide global API key remains the break-glass/admin override.
    if identity.method == "api_key" and identity.api_key_delegated is False:
        return identity

    # Backward compatibility: without role accounts or organization policies,
    # protected role-gated operations keep the previous single-admin behavior.
    if not rbac_is_enabled():
        return RequestIdentity(
            subject=identity.subject,
            role=ROLE_ADMIN,
            method=identity.method,
            organization_id=identity.organization_id,
            api_key_delegated=identity.api_key_delegated,
        )

    if identity.role != ROLE_ADMIN and identity.role not in set(allowed_roles):
        required = ", ".join(sorted(set(allowed_roles)))
        raise HTTPException(
            status_code=403,
            detail=(
                f"RBAC role '{identity.role}' is not allowed for this operation. "
                f"Required role: {required} or admin."
            ),
        )

    if permission is not None:
        try:
            permissions = effective_role_permissions(
                identity.organization_id,
                identity.role,
            )
        except OrganizationRbacPolicyError as exc:
            raise HTTPException(
                status_code=503,
                detail="Organization RBAC policy configuration is invalid.",
            ) from exc
        if "*" not in permissions and permission not in permissions:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"RBAC role '{identity.role}' is denied permission "
                    f"'{permission}' in organization '{identity.organization_id}'."
                ),
            )

    return identity
