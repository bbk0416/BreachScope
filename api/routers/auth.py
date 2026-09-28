"""Operator authentication endpoints for the BreachScope web console."""
from __future__ import annotations

import asyncio
import hmac
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from api.rbac import (
    OrganizationRbacPolicyError,
    configured_organization_rbac_policies,
    effective_role_permissions,
    organization_rbac_policy_settings_present,
    rbac_is_enabled,
)
from api.services.audit_log import AuditLogService
from api.services.auth_rate_limit import AuthRateLimiter
from api.services.oidc_auth import (
    OIDC_FLOW_COOKIE_NAME,
    OidcAuthorizationError,
    OidcConfigurationError,
    OidcError,
    build_authorization_url,
    configured_oidc_config,
    configured_oidc_roles,
    exchange_code_for_tokens,
    fetch_discovery,
    map_claims_to_organization,
    map_claims_to_role,
    new_oidc_flow,
    oidc_is_configured,
    oidc_settings_present,
    verify_id_token,
    verify_oidc_flow_token,
)
from api.services.organization_scope import configured_default_organization
from api.services.scim_directory import (
    ScimDirectoryError,
    ScimUserDirectory,
    scim_is_configured,
)
from api.security import (
    SESSION_COOKIE_NAME,
    ApiKeyConfigurationError,
    api_key_auth_is_configured,
    auth_is_enabled,
    client_ip_from_request,
    configured_admin_password,
    configured_api_key,
    configured_organization_api_keys,
    configured_role_password,
    configured_role_passwords,
    create_session_token,
    organization_api_key_settings_present,
    request_is_authenticated,
    resolve_api_key_credential,
    session_cookie_secure,
    session_ttl_seconds,
    trusted_proxy_ips as _trusted_proxy_ips,
    verify_session_token,
)

router = APIRouter()
AUTHENTICATED_ADMIN_SUBJECT = "admin"


class LoginRequest(BaseModel):
    password: str
    # Fixed identities only. Unknown names deliberately fall back to admin so
    # callers cannot invent arbitrary audit/session subjects.
    username: Optional[str] = "admin"


def _resolve_login_identity(username: str | None) -> tuple[str, str, str]:
    requested = str(username or "admin").strip().lower()
    if requested in {"author", "reviewer", "operator"}:
        return requested, requested, configured_role_password(requested)
    return AUTHENTICATED_ADMIN_SUBJECT, "admin", configured_admin_password()


# BREACHSCOPE_P2_06G_TRUSTED_PROXY_RATE_LIMIT_V1
def trusted_proxy_ips() -> set[str]:
    """Backward-compatible wrapper for the shared trusted-proxy parser."""
    return _trusted_proxy_ips()


def client_ip_for_rate_limit(request: Request) -> str:
    """Backward-compatible wrapper for the shared trusted-proxy IP resolver."""
    return client_ip_from_request(request)


@router.get("/auth/status", response_class=JSONResponse)
async def auth_status(request: Request):
    """Return auth mode and current browser-session status."""
    authenticated, method = request_is_authenticated(request)
    cookie_payload = (
        verify_session_token(request.cookies.get(SESSION_COOKIE_NAME))
        if authenticated and method == "session"
        else None
    )
    api_key_credential = (
        resolve_api_key_credential(request)
        if authenticated and method == "api_key"
        else None
    )
    active_organization_id = (
        api_key_credential.organization_id
        if api_key_credential is not None
        else (
            str(cookie_payload.get("org"))
            if cookie_payload and cookie_payload.get("org")
            else configured_default_organization()
        )
    )
    try:
        organization_rbac_policies = configured_organization_rbac_policies()
        organization_rbac_policy_config_valid = True
    except OrganizationRbacPolicyError:
        organization_rbac_policies = {}
        organization_rbac_policy_config_valid = False

    active_role = (
        "admin"
        if method == "api_key"
        else (
            str(cookie_payload.get("role") or "admin").strip().lower()
            if cookie_payload
            else ("admin" if not auth_is_enabled() else "none")
        )
    )
    if (
        method == "api_key"
        and api_key_credential is not None
        and api_key_credential.delegated is False
    ):
        active_permissions = ["*"]
    elif not auth_is_enabled():
        active_permissions = ["*"]
    elif authenticated and organization_rbac_policy_config_valid:
        try:
            active_permissions = sorted(
                effective_role_permissions(
                    active_organization_id,
                    active_role,
                )
            )
        except OrganizationRbacPolicyError:
            active_permissions = []
            organization_rbac_policy_config_valid = False
    else:
        active_permissions = []

    try:
        organization_api_keys = configured_organization_api_keys()
        organization_api_key_config_valid = True
    except ApiKeyConfigurationError:
        organization_api_keys = {}
        organization_api_key_config_valid = False

    return {
        "success": True,
        "auth_required": auth_is_enabled(),
        "api_key_enabled": api_key_auth_is_configured(),
        "global_api_key_enabled": bool(configured_api_key()),
        "organization_api_key_settings_present": (
            organization_api_key_settings_present()
        ),
        "organization_api_key_config_valid": (
            organization_api_key_config_valid
        ),
        "organization_api_key_count": len(organization_api_keys),
        "password_login_enabled": bool(
            configured_admin_password() or configured_role_passwords()
        ),
        "rbac_enabled": rbac_is_enabled(),
        "configured_roles": sorted(set(configured_role_passwords()) | set(configured_oidc_roles())),
        "organization_rbac_policy_settings_present": (
            organization_rbac_policy_settings_present()
        ),
        "organization_rbac_policy_config_valid": (
            organization_rbac_policy_config_valid
        ),
        "organization_rbac_policy_count": len(organization_rbac_policies),
        "active_permissions": active_permissions,
        "oidc_settings_present": oidc_settings_present(),
        "oidc_login_enabled": oidc_is_configured(),
        "scim_provisioning_enabled": scim_is_configured(),
        "scim_oidc_enforced": (
            scim_is_configured() and oidc_is_configured()
        ),
        "oidc_login_url": "/api/auth/oidc/login" if oidc_is_configured() else None,
        "authenticated": authenticated,
        "auth_method": method,
        "active_organization_id": active_organization_id,
        "api_key_delegated": (
            api_key_credential.delegated
            if api_key_credential is not None
            else None
        ),
        "session_subject": cookie_payload.get("sub") if cookie_payload else None,
        "session_role": cookie_payload.get("role") if cookie_payload else None,
        "session_authn": cookie_payload.get("authn") if cookie_payload else None,
        "session_organization_id": (
            cookie_payload.get("org") if cookie_payload else None
        ),
        "default_organization_id": configured_default_organization(),
        "session_expires_at": cookie_payload.get("exp") if cookie_payload else None,
        "session_ttl_seconds": session_ttl_seconds(),
    }


@router.post("/auth/login", response_class=JSONResponse)
async def login(payload: LoginRequest, request: Request, response: Response):
    """Create an HttpOnly browser session when BS_ADMIN_PASSWORD is configured."""
    principal, role, expected = _resolve_login_identity(payload.username)
    audit = AuditLogService()
    limiter = AuthRateLimiter()
    client_ip = client_ip_for_rate_limit(request)
    limit_key = limiter.make_key(client_ip, principal)
    lock_status = limiter.status(limit_key)
    if not lock_status.allowed:
        audit.record(
            "auth.login",
            request=request,
            status="failure",
            details={"reason": "locked_out", "username": principal, "retry_after_seconds": lock_status.retry_after_seconds},
        )
        raise HTTPException(status_code=429, detail=f"Too many failed login attempts. Try again in {lock_status.retry_after_seconds} seconds.")
    if not expected:
        audit.record("auth.login", request=request, status="failure", details={"reason": "password_login_disabled", "username": principal})
        raise HTTPException(
            status_code=400,
            detail=f"Password login is not enabled for role '{role}'.",
        )
    if not hmac.compare_digest(payload.password, expected):
        failure = limiter.record_failure(limit_key)
        audit.record(
            "auth.login",
            request=request,
            status="failure",
            details={
                "reason": "invalid_password",
                "username": principal,
                "failures": failure.failures,
                "locked_until": failure.locked_until,
                "retry_after_seconds": failure.retry_after_seconds,
            },
        )
        if not failure.allowed:
            raise HTTPException(status_code=429, detail=f"Too many failed login attempts. Try again in {failure.retry_after_seconds} seconds.")
        raise HTTPException(status_code=401, detail="Invalid password.")

    limiter.clear(limit_key)
    organization_id = configured_default_organization()
    token = create_session_token(
        subject=principal,
        role=role,
        organization_id=organization_id,
    )
    max_age = session_ttl_seconds()
    response = JSONResponse(
        {
            "success": True,
            "authenticated": True,
            "auth_method": "session",
            "session_subject": principal,
            "session_role": role,
            "session_organization_id": organization_id,
            "session_ttl_seconds": max_age,
        }
    )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=True,
        secure=session_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    audit.record(
        "auth.login",
        request=request,
        status="success",
        actor=principal,
        auth_method="session",
        details={
            "username": principal,
            "role": role,
            "organization_id": organization_id,
            "ttl_seconds": max_age,
        },
    )
    return response


@router.get("/auth/oidc/login")
async def oidc_login(request: Request, next: str = "/"):
    """Start an OIDC Authorization Code + PKCE login flow."""
    audit = AuditLogService()
    try:
        config = configured_oidc_config()
        metadata = await asyncio.to_thread(fetch_discovery, config)
        flow, flow_token = new_oidc_flow(next)
        authorization_url = build_authorization_url(config, metadata, flow)
    except OidcConfigurationError as exc:
        audit.record("auth.oidc.start", request=request, status="failure", details={"reason": "configuration_error"})
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except OidcError as exc:
        audit.record("auth.oidc.start", request=request, status="failure", details={"reason": "provider_error"})
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    response = RedirectResponse(authorization_url, status_code=302)
    response.set_cookie(
        OIDC_FLOW_COOKIE_NAME,
        flow_token,
        max_age=600,
        httponly=True,
        secure=session_cookie_secure(request),
        samesite="lax",
        path="/api/auth/oidc",
    )
    audit.record("auth.oidc.start", request=request, status="success", auth_method="oidc")
    return response


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
):
    """Complete OIDC login, map the identity to one BreachScope role, and issue bs_session."""
    audit = AuditLogService()
    flow = verify_oidc_flow_token(request.cookies.get(OIDC_FLOW_COOKIE_NAME))
    if not flow or not state or not hmac.compare_digest(str(flow.get("state") or ""), state):
        audit.record("auth.oidc.callback", request=request, status="failure", details={"reason": "invalid_state"})
        raise HTTPException(status_code=401, detail="OIDC state verification failed.")
    if error:
        audit.record("auth.oidc.callback", request=request, status="failure", details={"reason": "provider_denied"})
        raise HTTPException(status_code=401, detail="OIDC provider denied authentication.")
    if not code:
        audit.record("auth.oidc.callback", request=request, status="failure", details={"reason": "missing_code"})
        raise HTTPException(status_code=400, detail="OIDC authorization code is missing.")

    try:
        config = configured_oidc_config()
        metadata = await asyncio.to_thread(fetch_discovery, config)
        tokens = await asyncio.to_thread(
            exchange_code_for_tokens,
            config,
            metadata,
            code=code,
            code_verifier=str(flow["code_verifier"]),
        )
        claims = await asyncio.to_thread(
            verify_id_token,
            config,
            metadata,
            id_token=str(tokens["id_token"]),
            nonce=str(flow["nonce"]),
        )
        subject_value = str(claims.get("sub") or "")
        if not subject_value or len(subject_value) > 512:
            raise OidcAuthorizationError("OIDC subject is invalid.")
        if scim_is_configured():
            scim_identity = ScimUserDirectory().oidc_identity(
                subject_value
            )
            if scim_identity is None:
                raise OidcAuthorizationError(
                    "OIDC identity is not active in the SCIM directory."
                )
            role, organization_id = scim_identity
        else:
            role = map_claims_to_role(claims, config)
            organization_id = map_claims_to_organization(claims, config)
    except OidcAuthorizationError as exc:
        audit.record("auth.oidc.callback", request=request, status="failure", details={"reason": "identity_mapping_denied"})
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except OidcConfigurationError as exc:
        audit.record("auth.oidc.callback", request=request, status="failure", details={"reason": "configuration_error"})
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ScimDirectoryError as exc:
        audit.record("auth.oidc.callback", request=request, status="failure", details={"reason": "scim_directory_error"})
        raise HTTPException(status_code=503, detail="SCIM user directory is unavailable.") from exc
    except OidcError as exc:
        audit.record("auth.oidc.callback", request=request, status="failure", details={"reason": "provider_or_token_error"})
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    subject = "oidc:" + subject_value
    try:
        expires_at = int(claims["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="OIDC token expiry is invalid.") from exc
    max_age = min(session_ttl_seconds(), max(1, expires_at - int(time.time())))
    session_token = create_session_token(
        subject=subject,
        role=role,
        ttl_seconds=max_age,
        authn="oidc",
        organization_id=organization_id,
    )
    response = RedirectResponse(str(flow.get("next") or "/"), status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        max_age=max_age,
        httponly=True,
        secure=session_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(OIDC_FLOW_COOKIE_NAME, path="/api/auth/oidc")
    audit.record(
        "auth.oidc.callback",
        request=request,
        status="success",
        actor=subject,
        auth_method="oidc",
        details={
            "role": role,
            "organization_id": organization_id,
            "ttl_seconds": max_age,
        },
    )
    return response


@router.post("/auth/logout", response_class=JSONResponse)
async def logout(request: Request):
    """Clear the browser session cookie."""
    AuditLogService().record("auth.logout", request=request, status="success")
    response = JSONResponse({"success": True, "authenticated": False})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
