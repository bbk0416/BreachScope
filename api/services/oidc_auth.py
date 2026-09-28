"""Optional OpenID Connect login support for BreachScope."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient

from api.services.scim_directory import (
    ScimDirectoryError,
    ScimUserDirectory,
    scim_group_store_path,
    scim_is_configured,
    scim_user_store_path,
)
from api.services.organization_scope import (
    configured_default_organization,
    normalize_organization_id,
)


OIDC_FLOW_COOKIE_NAME = "bs_oidc_flow"
DEFAULT_FLOW_TTL_SECONDS = 10 * 60
SUPPORTED_ID_TOKEN_ALGORITHMS = {
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
}
KNOWN_ROLES = {"admin", "author", "reviewer", "operator"}
ROLE_VALUE_ENV = {
    "admin": "BS_OIDC_ADMIN_VALUES",
    "author": "BS_OIDC_AUTHOR_VALUES",
    "reviewer": "BS_OIDC_REVIEWER_VALUES",
    "operator": "BS_OIDC_OPERATOR_VALUES",
}


class OidcError(RuntimeError):
    """Base class for fail-closed OIDC errors."""


class OidcConfigurationError(OidcError):
    pass


class OidcProtocolError(OidcError):
    pass


class OidcAuthorizationError(OidcError):
    pass


@dataclass(frozen=True)
class OidcConfig:
    issuer_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: tuple[str, ...]
    role_claim: str
    organization_claim: str
    default_role: str
    role_values: Mapping[str, frozenset[str]]
    token_auth_method: str


def _env(name: str, env: Mapping[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    return str(source.get(name, "") or "").strip()


def _normalize_issuer(value: str) -> str:
    return value.rstrip("/")


def oidc_settings_present(env: Mapping[str, str] | None = None) -> bool:
    return any(
        _env(name, env)
        for name in (
            "BS_OIDC_ISSUER_URL",
            "BS_OIDC_CLIENT_ID",
            "BS_OIDC_CLIENT_SECRET",
            "BS_OIDC_REDIRECT_URI",
            "BS_OIDC_ORGANIZATION_CLAIM",
            "BS_OIDC_DEFAULT_ROLE",
            "BS_OIDC_ADMIN_VALUES",
            "BS_OIDC_AUTHOR_VALUES",
            "BS_OIDC_REVIEWER_VALUES",
            "BS_OIDC_OPERATOR_VALUES",
            "BS_OIDC_TOKEN_AUTH_METHOD",
        )
    )


def _is_https_or_loopback(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.netloc:
        return True
    return (
        parsed.scheme == "http"
        and (parsed.hostname or "").casefold() in {"localhost", "127.0.0.1", "::1"}
    )


def _csv_values(name: str, env: Mapping[str, str] | None = None) -> frozenset[str]:
    return frozenset(
        value.strip()
        for value in _env(name, env).split(",")
        if value.strip()
    )


def configured_oidc_config(env: Mapping[str, str] | None = None) -> OidcConfig:
    issuer = _normalize_issuer(_env("BS_OIDC_ISSUER_URL", env))
    client_id = _env("BS_OIDC_CLIENT_ID", env)
    redirect_uri = _env("BS_OIDC_REDIRECT_URI", env)
    session_secret = _env("BS_SESSION_SECRET", env)
    missing = [
        name
        for name, value in (
            ("BS_OIDC_ISSUER_URL", issuer),
            ("BS_OIDC_CLIENT_ID", client_id),
            ("BS_OIDC_REDIRECT_URI", redirect_uri),
            ("BS_SESSION_SECRET", session_secret),
        )
        if not value
    ]
    if missing:
        raise OidcConfigurationError(
            "OIDC requires " + ", ".join(missing) + "."
        )
    if not _is_https_or_loopback(issuer):
        raise OidcConfigurationError(
            "BS_OIDC_ISSUER_URL must use HTTPS (HTTP is allowed only for loopback development)."
        )
    if not _is_https_or_loopback(redirect_uri):
        raise OidcConfigurationError(
            "BS_OIDC_REDIRECT_URI must use HTTPS (HTTP is allowed only for loopback development)."
        )

    scopes = tuple(
        dict.fromkeys(
            value
            for value in (_env("BS_OIDC_SCOPES", env) or "openid profile email").split()
            if value
        )
    )
    if "openid" not in scopes:
        scopes = ("openid",) + scopes

    role_claim = _env("BS_OIDC_ROLE_CLAIM", env) or "groups"
    organization_claim = _env("BS_OIDC_ORGANIZATION_CLAIM", env)
    default_role = (_env("BS_OIDC_DEFAULT_ROLE", env) or "").casefold()
    if default_role and default_role not in KNOWN_ROLES:
        raise OidcConfigurationError(
            "BS_OIDC_DEFAULT_ROLE must be admin, author, reviewer, operator, or unset."
        )

    client_secret = _env("BS_OIDC_CLIENT_SECRET", env)
    token_auth_method = (_env("BS_OIDC_TOKEN_AUTH_METHOD", env) or "").casefold()
    if not token_auth_method:
        token_auth_method = "client_secret_basic" if client_secret else "none"
    if token_auth_method not in {"client_secret_basic", "client_secret_post", "none"}:
        raise OidcConfigurationError(
            "BS_OIDC_TOKEN_AUTH_METHOD must be client_secret_basic, client_secret_post, or none."
        )
    if token_auth_method != "none" and not client_secret:
        raise OidcConfigurationError(
            f"{token_auth_method} requires BS_OIDC_CLIENT_SECRET."
        )

    role_values = {
        role: _csv_values(env_name, env)
        for role, env_name in ROLE_VALUE_ENV.items()
    }
    if (
        not scim_is_configured(env)
        and not default_role
        and not any(role_values.values())
    ):
        raise OidcConfigurationError(
            "OIDC requires at least one role mapping, BS_OIDC_DEFAULT_ROLE, or configured SCIM provisioning."
        )

    return OidcConfig(
        issuer_url=issuer,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scopes=scopes,
        role_claim=role_claim,
        organization_claim=organization_claim,
        default_role=default_role,
        role_values=role_values,
        token_auth_method=token_auth_method,
    )


def oidc_is_configured(env: Mapping[str, str] | None = None) -> bool:
    if not oidc_settings_present(env):
        return False
    try:
        configured_oidc_config(env)
    except OidcConfigurationError:
        return False
    return True


def configured_oidc_roles(env: Mapping[str, str] | None = None) -> list[str]:
    if not oidc_settings_present(env):
        return []
    try:
        config = configured_oidc_config(env)
    except OidcConfigurationError:
        return []
    roles = {
        role
        for role, values in config.role_values.items()
        if values
    }
    if config.default_role:
        roles.add(config.default_role)
    if scim_is_configured(env):
        try:
            roles.update(
                ScimUserDirectory(
                    path=scim_user_store_path(env),
                    group_path=scim_group_store_path(env),
                ).active_roles()
            )
        except ScimDirectoryError:
            pass
    return sorted(roles)


def oidc_role_is_configured(role: str, env: Mapping[str, str] | None = None) -> bool:
    return str(role or "").strip().casefold() in set(configured_oidc_roles(env))


def _flow_secret() -> bytes:
    secret = _env("BS_SESSION_SECRET")
    if not secret:
        raise OidcConfigurationError("BS_SESSION_SECRET is required for OIDC.")
    return secret.encode("utf-8")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + ("=" * (-len(data) % 4)))


def _sanitize_next_path(value: str | None) -> str:
    candidate = str(value or "/").strip()
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\r" in candidate
        or "\n" in candidate
    ):
        return "/"
    return candidate


def create_oidc_flow_token(
    *,
    state: str,
    nonce: str,
    code_verifier: str,
    next_path: str = "/",
    now: int | None = None,
    ttl_seconds: int = DEFAULT_FLOW_TTL_SECONDS,
) -> str:
    issued = int(now if now is not None else time.time())
    payload = {
        "typ": "breachscope-oidc-flow",
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "next": _sanitize_next_path(next_path),
        "iat": issued,
        "exp": issued + int(ttl_seconds),
    }
    encoded = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = hmac.new(_flow_secret(), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{_b64url_encode(signature)}"


def verify_oidc_flow_token(token: str | None, now: int | None = None) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    encoded, supplied = token.split(".", 1)
    expected = _b64url_encode(
        hmac.new(_flow_secret(), encoded.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(supplied, expected):
        return None
    try:
        payload = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if payload.get("typ") != "breachscope-oidc-flow":
        return None
    current = int(now if now is not None else time.time())
    try:
        if int(payload.get("exp", 0)) < current:
            return None
    except (TypeError, ValueError):
        return None
    for key in ("state", "nonce", "code_verifier"):
        if not str(payload.get(key) or ""):
            return None
    payload["next"] = _sanitize_next_path(payload.get("next"))
    return payload


def new_oidc_flow(next_path: str = "/") -> tuple[dict[str, str], str]:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    challenge = _b64url_encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
    token = create_oidc_flow_token(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        next_path=next_path,
    )
    return {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "code_challenge": challenge,
        "next": _sanitize_next_path(next_path),
    }, token


def _fetch_json(
    url: str,
    *,
    data: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Accept": "application/json", **dict(headers or {})},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OidcProtocolError("OIDC provider request failed.") from exc
    if len(raw) > 1024 * 1024:
        raise OidcProtocolError("OIDC provider response is too large.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OidcProtocolError("OIDC provider returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise OidcProtocolError("OIDC provider returned an invalid JSON object.")
    return payload


def fetch_discovery(config: OidcConfig) -> dict[str, Any]:
    metadata = _fetch_json(config.issuer_url + "/.well-known/openid-configuration")
    issuer = _normalize_issuer(str(metadata.get("issuer") or ""))
    if issuer != config.issuer_url:
        raise OidcProtocolError("OIDC discovery issuer does not match BS_OIDC_ISSUER_URL.")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        endpoint = str(metadata.get(key) or "")
        if not _is_https_or_loopback(endpoint):
            raise OidcProtocolError(f"OIDC discovery {key} is missing or unsafe.")
    return metadata


def build_authorization_url(
    config: OidcConfig,
    metadata: Mapping[str, Any],
    flow: Mapping[str, str],
) -> str:
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": " ".join(config.scopes),
            "state": flow["state"],
            "nonce": flow["nonce"],
            "code_challenge": flow["code_challenge"],
            "code_challenge_method": "S256",
        }
    )
    return str(metadata["authorization_endpoint"]) + "?" + query


def exchange_code_for_tokens(
    config: OidcConfig,
    metadata: Mapping[str, Any],
    *,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "client_id": config.client_id,
        "code_verifier": code_verifier,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if config.token_auth_method == "client_secret_basic":
        user = urllib.parse.quote_plus(config.client_id)
        password = urllib.parse.quote_plus(config.client_secret)
        basic = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic " + basic
    elif config.token_auth_method == "client_secret_post":
        form["client_secret"] = config.client_secret
    payload = _fetch_json(
        str(metadata["token_endpoint"]),
        data=urllib.parse.urlencode(form).encode("ascii"),
        headers=headers,
    )
    if not str(payload.get("id_token") or ""):
        raise OidcProtocolError("OIDC token response does not contain id_token.")
    return payload


def verify_id_token(
    config: OidcConfig,
    metadata: Mapping[str, Any],
    *,
    id_token: str,
    nonce: str,
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise OidcProtocolError("OIDC id_token header is invalid.") from exc
    algorithm = str(header.get("alg") or "")
    if algorithm not in SUPPORTED_ID_TOKEN_ALGORITHMS:
        raise OidcProtocolError("OIDC id_token uses an unsupported signing algorithm.")
    try:
        signing_key = PyJWKClient(str(metadata["jwks_uri"])).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=[algorithm],
            audience=config.client_id,
            issuer=config.issuer_url,
            options={"require": ["exp", "iat", "iss", "sub", "aud", "nonce"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcProtocolError("OIDC id_token verification failed.") from exc
    if not hmac.compare_digest(str(claims.get("nonce") or ""), nonce):
        raise OidcProtocolError("OIDC nonce verification failed.")
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1:
        if str(claims.get("azp") or "") != config.client_id:
            raise OidcProtocolError("OIDC azp is required for a multi-audience id_token.")
    elif claims.get("azp") and str(claims.get("azp")) != config.client_id:
        raise OidcProtocolError("OIDC azp does not match the configured client.")
    return dict(claims)


def _claim_values(claims: Mapping[str, Any], claim_path: str) -> set[str]:
    current: Any = claims
    for part in claim_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return set()
        current = current[part]
    if isinstance(current, str):
        return {current}
    if isinstance(current, (list, tuple, set)):
        return {str(value) for value in current if str(value)}
    return set()


def map_claims_to_role(claims: Mapping[str, Any], config: OidcConfig) -> str:
    values = _claim_values(claims, config.role_claim)
    matched = [
        role
        for role, accepted in config.role_values.items()
        if values.intersection(accepted)
    ]
    if "admin" in matched:
        return "admin"
    non_admin = [role for role in matched if role != "admin"]
    if len(non_admin) == 1:
        return non_admin[0]
    if len(non_admin) > 1:
        raise OidcAuthorizationError(
            "OIDC identity maps to multiple non-admin BreachScope roles."
        )
    if config.default_role:
        return config.default_role
    raise OidcAuthorizationError(
        "OIDC identity does not map to a BreachScope role."
    )


def map_claims_to_organization(
    claims: Mapping[str, Any],
    config: OidcConfig,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """Map one OIDC identity to exactly one active BreachScope organization."""
    if not config.organization_claim:
        return configured_default_organization(env)
    values = _claim_values(claims, config.organization_claim)
    if len(values) != 1:
        raise OidcAuthorizationError(
            "OIDC organization claim must resolve to exactly one organization."
        )
    try:
        return normalize_organization_id(next(iter(values)), default=None)
    except ValueError as exc:
        raise OidcAuthorizationError("OIDC organization claim is invalid.") from exc
