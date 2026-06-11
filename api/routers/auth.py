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
    configured_admin_password,
    configured_api_key,
    create_session_token,
    request_is_authenticated,
    session_cookie_secure,
    session_ttl_seconds,
    verify_session_token,
)

router = APIRouter()


class LoginRequest(BaseModel):
    password: str
    username: Optional[str] = "admin"


@router.get("/auth/status", response_class=JSONResponse)
async def auth_status(request: Request):
    """Return auth mode and current browser-session status."""
    authenticated, method = request_is_authenticated(request)
    cookie_payload = verify_session_token(request.cookies.get(SESSION_COOKIE_NAME))
    return {
        "success": True,
        "auth_required": auth_is_enabled(),
        "api_key_enabled": bool(configured_api_key()),
        "password_login_enabled": bool(configured_admin_password()),
        "authenticated": authenticated,
        "auth_method": method,
        "session_subject": cookie_payload.get("sub") if cookie_payload else None,
        "session_expires_at": cookie_payload.get("exp") if cookie_payload else None,
        "session_ttl_seconds": session_ttl_seconds(),
    }


@router.post("/auth/login", response_class=JSONResponse)
async def login(payload: LoginRequest, request: Request, response: Response):
    """Create an HttpOnly browser session when BS_ADMIN_PASSWORD is configured."""
    expected = configured_admin_password()
    audit = AuditLogService()
    limiter = AuthRateLimiter()
    username = (payload.username or "admin").strip() or "admin"
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
    limit_key = limiter.make_key(client_ip, username)
    lock_status = limiter.status(limit_key)
    if not lock_status.allowed:
        audit.record(
            "auth.login",
            request=request,
            status="failure",
            details={"reason": "locked_out", "username": username, "retry_after_seconds": lock_status.retry_after_seconds},
        )
        raise HTTPException(status_code=429, detail=f"Too many failed login attempts. Try again in {lock_status.retry_after_seconds} seconds.")
    if not expected:
        audit.record("auth.login", request=request, status="failure", details={"reason": "password_login_disabled", "username": username})
        raise HTTPException(status_code=400, detail="Password login is not enabled. Set BS_ADMIN_PASSWORD first.")
    if not hmac.compare_digest(payload.password, expected):
        failure = limiter.record_failure(limit_key)
        audit.record(
            "auth.login",
            request=request,
            status="failure",
            details={
                "reason": "invalid_password",
                "username": username,
                "failures": failure.failures,
                "locked_until": failure.locked_until,
                "retry_after_seconds": failure.retry_after_seconds,
            },
        )
        if not failure.allowed:
            raise HTTPException(status_code=429, detail=f"Too many failed login attempts. Try again in {failure.retry_after_seconds} seconds.")
        raise HTTPException(status_code=401, detail="Invalid password.")

    limiter.clear(limit_key)
    token = create_session_token(subject=username)
    max_age = session_ttl_seconds()
    response = JSONResponse(
        {
            "success": True,
            "authenticated": True,
            "auth_method": "session",
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
    audit.record("auth.login", request=request, status="success", actor=username, auth_method="session", details={"username": username, "ttl_seconds": max_age})
    return response


@router.post("/auth/logout", response_class=JSONResponse)
async def logout(request: Request):
    """Clear the browser session cookie."""
    AuditLogService().record("auth.logout", request=request, status="success")
    response = JSONResponse({"success": True, "authenticated": False})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
