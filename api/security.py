"""Optional API-key and browser-session protection for productized deployments."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Iterable, Mapping

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from api.services.oidc_auth import (
    oidc_is_configured,
    oidc_role_is_configured,
    oidc_settings_present,
)
from api.services.scim_directory import (
    ScimDirectoryError,
    ScimUserDirectory,
    scim_is_configured,
)
from api.services.organization_scope import (
    configured_default_organization,
    normalize_organization_id,
)


SESSION_COOKIE_NAME = "bs_session"
DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60
ORGANIZATION_API_KEYS_ENV = "BS_ORGANIZATION_API_KEYS"


class ApiKeyConfigurationError(ValueError):
    """Raised when API-key delegation settings are malformed or ambiguous."""


class ApiKeyOrganizationSelectorError(ValueError):
    """Raised when an API-key organization selector is invalid."""


class ApiKeyOrganizationAccessError(PermissionError):
    """Raised when an organization-bound API key requests another organization."""

    def __init__(self, organization_id: str):
        super().__init__("API key is not delegated to the requested organization.")
        self.organization_id = organization_id


@dataclass(frozen=True)
class ApiKeyCredential:
    organization_id: str
    delegated: bool


SAFE_PATH_PREFIXES = (
    "/",
    "/api/health",
    # BREACHSCOPE_P2_06E_API_INFO_AUTH_BOUNDARY_V1
    # /api/info exposes operational/auth/path metadata and is intentionally
    # protected whenever runtime authentication is enabled.
    "/api/auth",
    "/api/scim/v2",
    "/api/docs",
    "/api/redoc",
    "/openapi.json",
)


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def configured_api_key() -> str:
    return _env("BS_API_KEY")


def organization_api_key_settings_present(
    env: Mapping[str, str] | None = None,
) -> bool:
    source = os.environ if env is None else env
    raw = str(source.get(ORGANIZATION_API_KEYS_ENV, "") or "").strip()
    if not raw:
        return False
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return True
    return not (isinstance(payload, dict) and not payload)


def configured_organization_api_keys(
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return normalized organization-to-secret API key bindings."""
    source = os.environ if env is None else env
    raw = str(source.get(ORGANIZATION_API_KEYS_ENV, "") or "").strip()
    if not raw:
        return {}
    def _unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ApiKeyConfigurationError(
                    "BS_ORGANIZATION_API_KEYS contains duplicate organization entries."
                )
            obj[key] = value
        return obj

    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise ApiKeyConfigurationError(
            "BS_ORGANIZATION_API_KEYS must be a JSON object."
        ) from exc
    if not isinstance(payload, dict):
        raise ApiKeyConfigurationError(
            "BS_ORGANIZATION_API_KEYS must be a JSON object."
        )

    result: dict[str, str] = {}
    secret_owners: dict[str, str] = {}
    global_key = str(source.get("BS_API_KEY", "") or "").strip()
    for raw_org, raw_secret in payload.items():
        try:
            organization_id = normalize_organization_id(
                raw_org,
                default=None,
            )
        except ValueError as exc:
            raise ApiKeyConfigurationError(
                "BS_ORGANIZATION_API_KEYS contains an invalid organization ID."
            ) from exc
        if organization_id in result:
            raise ApiKeyConfigurationError(
                "BS_ORGANIZATION_API_KEYS contains duplicate normalized organizations."
            )
        if not isinstance(raw_secret, str) or not raw_secret.strip():
            raise ApiKeyConfigurationError(
                "BS_ORGANIZATION_API_KEYS values must be non-empty strings."
            )
        secret = raw_secret.strip()
        if global_key and hmac.compare_digest(secret, global_key):
            raise ApiKeyConfigurationError(
                "Organization API keys must not reuse BS_API_KEY."
            )
        if secret in secret_owners:
            raise ApiKeyConfigurationError(
                "Organization API keys must be unique per organization."
            )
        result[organization_id] = secret
        secret_owners[secret] = organization_id
    return result


def api_key_auth_is_configured() -> bool:
    try:
        organization_keys = configured_organization_api_keys()
    except ApiKeyConfigurationError:
        return False
    return bool(configured_api_key() or organization_keys)


def configured_admin_password() -> str:
    return _env("BS_ADMIN_PASSWORD")


def configured_role_password(role: str) -> str:
    env_name = {
        "author": "BS_AUTHOR_PASSWORD",
        "reviewer": "BS_REVIEWER_PASSWORD",
        "operator": "BS_OPERATOR_PASSWORD",
    }.get(str(role or "").strip().lower(), "")
    return _env(env_name) if env_name else ""


def configured_role_passwords() -> dict[str, str]:
    return {
        role: password
        for role in ("author", "reviewer", "operator")
        if (password := configured_role_password(role))
    }


def password_login_is_enabled() -> bool:
    return bool(configured_admin_password() or configured_role_passwords())


# BREACHSCOPE_P0_12_AUTH_FAIL_CLOSED_V1
def _is_production_mode() -> bool:
    return _env("BS_DEPLOYMENT_MODE").casefold() in {"production", "prod"}


def _local_credentials_configured() -> bool:
    return bool(
        api_key_auth_is_configured()
        or configured_admin_password()
        or configured_role_passwords()
    )


def _credentials_configured() -> bool:
    return _local_credentials_configured() or oidc_is_configured()


def _production_auth_misconfigured() -> bool:
    return _is_production_mode() and not _credentials_configured()


def auth_is_enabled() -> bool:
    """Return True when auth is configured or production requires fail-closed auth."""
    return (
        _local_credentials_configured()
        or organization_api_key_settings_present()
        or oidc_settings_present()
        or _is_production_mode()
    )


# BREACHSCOPE_P2_06N_SHARED_TRUSTED_PROXY_IP_V1
def trusted_proxy_ips() -> set[str]:
    """Return exact proxy IPs allowed to contribute X-Forwarded-For data."""
    raw = _env("BS_TRUSTED_PROXY_IPS")
    if not raw:
        return set()

    trusted: set[str] = set()
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        try:
            trusted.add(str(ip_address(candidate)))
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address in BS_TRUSTED_PROXY_IPS: {candidate}"
            ) from exc
    return trusted


def client_ip_from_request(request: Request) -> str:
    """Resolve client IP without trusting arbitrary forwarding headers.

    The direct peer is authoritative by default. X-Forwarded-For is considered
    only when the direct peer is explicitly listed in BS_TRUSTED_PROXY_IPS. The
    chain is walked from right to left through trusted proxies, returning the
    first untrusted hop as the originating client.
    """
    peer = request.client.host if request.client else "unknown"
    try:
        current = str(ip_address(peer))
    except ValueError:
        return peer or "unknown"

    trusted = trusted_proxy_ips()
    if current not in trusted:
        return current

    forwarded = request.headers.get("x-forwarded-for", "")
    hops = [value.strip() for value in forwarded.split(",") if value.strip()]
    if not hops:
        return current

    direct_peer = current
    for candidate in reversed(hops):
        if current not in trusted:
            break
        try:
            current = str(ip_address(candidate))
        except ValueError:
            return direct_peer
    return current


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
    role_fallback = next(iter(configured_role_passwords().values()), "")
    return (
        _env("BS_SESSION_SECRET")
        or configured_api_key()
        or configured_admin_password()
        or role_fallback
        or "breachscope-dev-session-secret"
    )


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_session_token(
    subject: str = "admin",
    ttl_seconds: int | None = None,
    now: int | None = None,
    role: str | None = None,
    authn: str | None = None,
    organization_id: str | None = None,
) -> str:
    """Create a compact HMAC-signed session token.

    The token intentionally uses only the Python standard library. It is not a
    JWT implementation; it is a small signed payload for the built-in web UI.
    """
    issued_at = int(now if now is not None else time.time())
    ttl = int(ttl_seconds if ttl_seconds is not None else session_ttl_seconds())
    payload = {
        "sub": subject,
        "role": str(role or subject or "admin").strip().lower(),
        "authn": str(authn or "password").strip().lower(),
        "org": normalize_organization_id(
            organization_id,
            default=configured_default_organization(),
        ),
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
    """Extract API credentials from headers only."""
    api_key = request.headers.get("x-api-key", "").strip()
    if api_key:
        return api_key

    auth = request.headers.get("authorization", "").strip()
    if auth.casefold().startswith("bearer "):
        return auth[7:].strip()

    return ""


def resolve_api_key_credential(
    request: Request,
) -> ApiKeyCredential | None:
    """Resolve a global or organization-bound API credential without exposing it."""
    supplied = extract_api_key(request)
    if not supplied:
        return None

    organization_keys = configured_organization_api_keys()
    global_key = configured_api_key()
    raw_selector = request.headers.get("x-breachscope-organization")

    if global_key and hmac.compare_digest(supplied, global_key):
        try:
            organization_id = normalize_organization_id(
                raw_selector,
                default=configured_default_organization(),
            )
        except ValueError as exc:
            raise ApiKeyOrganizationSelectorError(
                "Invalid BreachScope organization selector."
            ) from exc
        return ApiKeyCredential(
            organization_id=organization_id,
            delegated=False,
        )

    matched_organization = None
    for organization_id, secret in organization_keys.items():
        if hmac.compare_digest(supplied, secret):
            matched_organization = organization_id
    if matched_organization is None:
        return None

    if raw_selector is not None and raw_selector.strip():
        try:
            requested = normalize_organization_id(
                raw_selector,
                default=None,
            )
        except ValueError as exc:
            raise ApiKeyOrganizationSelectorError(
                "Invalid BreachScope organization selector."
            ) from exc
        if requested != matched_organization:
            raise ApiKeyOrganizationAccessError(matched_organization)

    return ApiKeyCredential(
        organization_id=matched_organization,
        delegated=True,
    )


def _session_identity_is_enabled(payload: dict[str, object]) -> bool:
    role = str(payload.get("role") or payload.get("sub") or "admin").strip().lower()
    authn = str(payload.get("authn") or "password").strip().lower()
    if authn == "oidc":
        if not oidc_is_configured():
            return False
        if scim_is_configured():
            subject = str(payload.get("sub") or "")
            if not subject.startswith("oidc:"):
                return False
            try:
                identity = ScimUserDirectory().oidc_identity(
                    subject[len("oidc:"):]
                )
            except ScimDirectoryError:
                return False
            if identity is None:
                return False
            expected_role, expected_org = identity
            try:
                session_org = normalize_organization_id(
                    payload.get("org"),
                    default=configured_default_organization(),
                )
            except ValueError:
                return False
            return role == expected_role and session_org == expected_org
        return oidc_role_is_configured(role)
    if role == "admin":
        return bool(configured_admin_password())
    if role in {"author", "reviewer", "operator"}:
        return bool(configured_role_password(role))
    return False


def request_is_authenticated(request: Request) -> tuple[bool, str]:
    """Return (authenticated, method) for API key or browser session."""
    if extract_api_key(request):
        try:
            credential = resolve_api_key_credential(request)
        except (
            ApiKeyConfigurationError,
            ApiKeyOrganizationSelectorError,
            ApiKeyOrganizationAccessError,
        ):
            credential = None
        if credential is not None:
            return True, "api_key"

    session_payload = verify_session_token(
        request.cookies.get(SESSION_COOKIE_NAME)
    )
    if session_payload and _session_identity_is_enabled(session_payload):
        return True, "session"

    return False, "none"


def _public_when_auth_misconfigured(path: str) -> bool:
    """Keep only probes, static assets, and auth recovery routes public."""
    exact = {
        "/",
        "/api/auth/status",
        "/api/auth/login",
        "/api/auth/logout",
        "/api/health",
        "/api/health/live",
        "/api/health/ready",
        "/favicon.ico",
    }
    return (
        path in exact
        or path.startswith("/static/")
        or path == "/api/scim/v2"
        or path.startswith("/api/scim/v2/")
    )


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """Protect operator endpoints and fail closed on production auth misconfiguration."""

    def __init__(self, app, exempt_prefixes: Iterable[str] = SAFE_PATH_PREFIXES):
        super().__init__(app)
        self.exempt_prefixes = tuple(exempt_prefixes)

    async def dispatch(self, request: Request, call_next):
        if _production_auth_misconfigured():
            if _public_when_auth_misconfigured(request.url.path):
                return await call_next(request)
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "Production authentication is not configured.",
                    "code": "AUTH_MISCONFIGURED",
                },
            )

        if not auth_is_enabled() or self._is_exempt(request):
            return await call_next(request)

        supplied_api_key = extract_api_key(request)
        if supplied_api_key:
            try:
                credential = resolve_api_key_credential(request)
            except ApiKeyConfigurationError:
                return JSONResponse(
                    status_code=503,
                    content={
                        "success": False,
                        "error": "api_key_configuration_invalid",
                        "message": "API-key delegation configuration is invalid.",
                    },
                )
            except ApiKeyOrganizationSelectorError as exc:
                return JSONResponse(
                    status_code=400,
                    content={
                        "success": False,
                        "error": "invalid_organization_selector",
                        "message": str(exc),
                    },
                )
            except ApiKeyOrganizationAccessError as exc:
                try:
                    from api.services.audit_log import AuditLogService

                    AuditLogService().record(
                        "auth.denied",
                        request=request,
                        status="failure",
                        details={"reason": "organization_scope_denied"},
                    )
                except Exception:
                    pass
                return JSONResponse(
                    status_code=403,
                    content={
                        "success": False,
                        "error": "organization_scope_denied",
                        "message": str(exc),
                    },
                )
            if credential is not None:
                return await call_next(request)

        authenticated, _method = request_is_authenticated(request)
        if authenticated:
            return await call_next(request)

        try:
            from api.services.audit_log import AuditLogService

            AuditLogService().record(
                "auth.denied",
                request=request,
                status="failure",
                details={"reason": "missing_or_invalid_credentials"},
            )
        except Exception:
            pass

        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "error": "unauthorized",
                "message": (
                    "Authentication is required. Use X-API-Key, "
                    "Authorization: Bearer, or sign in to the web console."
                ),
            },
            headers={"WWW-Authenticate": "ApiKey"},
        )

    def _is_exempt(self, request: Request) -> bool:
        if request.method.upper() == "OPTIONS":
            return True
        path = request.url.path
        if path == "/":
            return True
        return any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in self.exempt_prefixes
            if prefix != "/"
        )

    @staticmethod
    def _extract_key(request: Request) -> str:
        # Backward-compatible hook used by older tests/imports.
        return extract_api_key(request)
