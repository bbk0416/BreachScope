"""Optional API-key and browser-session protection for productized deployments."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Iterable

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


SESSION_COOKIE_NAME = "bs_session"
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60

SAFE_PATH_PREFIXES = (
    "/",
    "/api/health",
    "/api/info",
    "/api/auth",
    "/api/docs",
    "/api/redoc",
    "/openapi.json",
)


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def configured_api_key() -> str:
    return _env("BS_API_KEY")


def configured_admin_password() -> str:
    return _env("BS_ADMIN_PASSWORD")


def auth_is_enabled() -> bool:
    """Return True when any operator-facing auth mode is configured."""
    return bool(configured_api_key() or configured_admin_password())


def session_ttl_seconds() -> int:
    raw = _env("BS_SESSION_TTL_SECONDS")
    if not raw:
        return DEFAULT_SESSION_TTL_SECONDS
    try:
        return max(300, int(raw))
    except ValueError:
        return DEFAULT_SESSION_TTL_SECONDS


def session_cookie_secure(request: Request | None = None) -> bool:
    raw = _env("BS_COOKIE_SECURE").lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return bool(request and request.url.scheme == "https")


def _session_secret() -> str:
    """Return signing secret for session cookies.

    BS_SESSION_SECRET is preferred so API keys and passwords can rotate without
    invalidating every session. In small local deployments it safely falls back to
    BS_API_KEY or BS_ADMIN_PASSWORD.
    """
    return _env("BS_SESSION_SECRET") or configured_api_key() or configured_admin_password() or "breachscope-dev-session-secret"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_session_token(subject: str = "admin", ttl_seconds: int | None = None, now: int | None = None) -> str:
    """Create a compact HMAC-signed session token.

    The token intentionally uses only the Python standard library. It is not a
    JWT implementation; it is a small signed payload for the built-in web UI.
    """
    issued_at = int(now if now is not None else time.time())
    ttl = int(ttl_seconds if ttl_seconds is not None else session_ttl_seconds())
    payload = {
        "sub": subject,
        "iat": issued_at,
        "exp": issued_at + ttl,
        "typ": "breachscope-session",
    }
    encoded = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(_session_secret().encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{_b64url_encode(signature)}"


def verify_session_token(token: str | None, now: int | None = None) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    encoded, supplied_sig = token.split(".", 1)
    expected_sig = _b64url_encode(
        hmac.new(_session_secret().encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(supplied_sig, expected_sig):
        return None
    try:
        payload = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if payload.get("typ") != "breachscope-session":
        return None
    current = int(now if now is not None else time.time())
    try:
        exp = int(payload.get("exp", 0))
    except (TypeError, ValueError):
        return None
    if exp < current:
        return None
    return payload


def extract_api_key(request: Request) -> str:
    api_key = request.headers.get("x-api-key", "").strip()
    if api_key:
        return api_key

    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()

    return request.query_params.get("api_key", "").strip()


def request_is_authenticated(request: Request) -> tuple[bool, str]:
    """Return (authenticated, method) for API key or browser session."""
    api_key = configured_api_key()
    supplied = extract_api_key(request)
    if api_key and supplied and hmac.compare_digest(supplied, api_key):
        return True, "api_key"

    if configured_admin_password() and verify_session_token(request.cookies.get(SESSION_COOKIE_NAME)):
        return True, "session"

    return False, "none"


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """Protect API endpoints when BS_API_KEY or BS_ADMIN_PASSWORD is configured.

    Authentication is intentionally disabled by default so local demos and tests
    keep working without setup. In shared or internet-facing deployments, set at
    least one of the following:

    * ``BS_API_KEY`` for automation/API clients
    * ``BS_ADMIN_PASSWORD`` for browser login with an HttpOnly session cookie

    API clients can send the key as ``X-API-Key``, ``Authorization: Bearer``, or
    ``?api_key=`` for browser download links. Browser users can sign in through
    ``/api/auth/login`` when ``BS_ADMIN_PASSWORD`` is configured.
    """

    def __init__(self, app, exempt_prefixes: Iterable[str] = SAFE_PATH_PREFIXES):
        super().__init__(app)
        self.exempt_prefixes = tuple(exempt_prefixes)

    async def dispatch(self, request: Request, call_next):
        if not auth_is_enabled() or self._is_exempt(request):
            return await call_next(request)

        authenticated, _method = request_is_authenticated(request)
        if authenticated:
            return await call_next(request)

        try:
            from api.services.audit_log import AuditLogService
            AuditLogService().record("auth.denied", request=request, status="failure", details={"reason": "missing_or_invalid_credentials"})
        except Exception:
            pass

        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "error": "unauthorized",
                "message": "Authentication is required. Use X-API-Key, Authorization: Bearer, or sign in to the web console.",
            },
            headers={"WWW-Authenticate": "ApiKey"},
        )

    def _is_exempt(self, request: Request) -> bool:
        if request.method.upper() == "OPTIONS":
            return True
        path = request.url.path
        if path == "/":
            return True
        return any(path == prefix or path.startswith(prefix + "/") for prefix in self.exempt_prefixes if prefix != "/")

    @staticmethod
    def _extract_key(request: Request) -> str:
        # Backward-compatible hook used by older tests/imports.
        return extract_api_key(request)
