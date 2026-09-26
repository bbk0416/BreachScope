"""Operator authentication endpoints for the BreachScope web console."""
from __future__ import annotations

import hmac
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from api.services.audit_log import AuditLogService
from api.services.auth_rate_limit import AuthRateLimiter
from api.security import (
    SESSION_COOKIE_NAME,
    auth_is_enabled,
    client_ip_from_request,
    configured_admin_password,
    configured_api_key,
    configured_role_password,
    configured_role_passwords,
    create_session_token,
    request_is_authenticated,
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
    return {
        "success": True,
        "auth_required": auth_is_enabled(),
        "api_key_enabled": bool(configured_api_key()),
        "password_login_enabled": bool(
            configured_admin_password() or configured_role_passwords()
        ),
        "rbac_enabled": bool(configured_role_passwords()),
        "configured_roles": sorted(configured_role_passwords()),
        "authenticated": authenticated,
        "auth_method": method,
        "session_subject": cookie_payload.get("sub") if cookie_payload else None,
        "session_role": cookie_payload.get("role") if cookie_payload else None,
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
    token = create_session_token(subject=principal, role=role)
    max_age = session_ttl_seconds()
    response = JSONResponse(
        {
            "success": True,
            "authenticated": True,
            "auth_method": "session",
            "session_subject": principal,
            "session_role": role,
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
        details={"username": principal, "role": role, "ttl_seconds": max_age},
    )
    return response


@router.post("/auth/logout", response_class=JSONResponse)
async def logout(request: Request):
    """Clear the browser session cookie."""
    AuditLogService().record("auth.logout", request=request, status="success")
    response = JSONResponse({"success": True, "authenticated": False})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
