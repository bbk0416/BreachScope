from __future__ import annotations

import time
import urllib.parse

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import setup_middleware
from api.routers import auth
from api.security import auth_is_enabled
from api.services import oidc_auth


OIDC_ENV_NAMES = (
    "BS_OIDC_ISSUER_URL",
    "BS_OIDC_CLIENT_ID",
    "BS_OIDC_CLIENT_SECRET",
    "BS_OIDC_REDIRECT_URI",
    "BS_OIDC_SCOPES",
    "BS_OIDC_ROLE_CLAIM",
    "BS_OIDC_DEFAULT_ROLE",
    "BS_OIDC_ADMIN_VALUES",
    "BS_OIDC_AUTHOR_VALUES",
    "BS_OIDC_REVIEWER_VALUES",
    "BS_OIDC_OPERATOR_VALUES",
    "BS_OIDC_TOKEN_AUTH_METHOD",
)


def _configure_oidc(monkeypatch, tmp_path) -> None:
    for name in OIDC_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    for name in (
        "BS_API_KEY",
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BS_OIDC_ISSUER_URL", "https://idp.example.test")
    monkeypatch.setenv("BS_OIDC_CLIENT_ID", "breachscope")
    monkeypatch.setenv(
        "BS_OIDC_REDIRECT_URI",
        "https://breachscope.example.test/api/auth/oidc/callback",
    )
    monkeypatch.setenv("BS_OIDC_OPERATOR_VALUES", "breachscope-operators")
    monkeypatch.setenv("BS_SESSION_SECRET", "unit-session-secret-long-enough")
    monkeypatch.setenv("BS_COOKIE_SECURE", "0")
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))


def _metadata() -> dict[str, str]:
    return {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "jwks_uri": "https://idp.example.test/jwks",
    }


def _client(monkeypatch, tmp_path) -> TestClient:
    _configure_oidc(monkeypatch, tmp_path)
    app = FastAPI()
    setup_middleware(app)
    app.include_router(auth.router, prefix="/api")
    return TestClient(app)


def test_oidc_config_requires_explicit_role_mapping(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    monkeypatch.delenv("BS_OIDC_OPERATOR_VALUES", raising=False)

    assert oidc_auth.oidc_settings_present() is True
    assert oidc_auth.oidc_is_configured() is False
    assert auth_is_enabled() is True
    with pytest.raises(oidc_auth.OidcConfigurationError):
        oidc_auth.configured_oidc_config()


def test_oidc_flow_token_is_signed_expiring_and_sanitizes_next(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    token = oidc_auth.create_oidc_flow_token(
        state="state",
        nonce="nonce",
        code_verifier="verifier",
        next_path="//evil.example/path",
        now=100,
        ttl_seconds=30,
    )

    payload = oidc_auth.verify_oidc_flow_token(token, now=110)
    assert payload is not None
    assert payload["next"] == "/"
    assert oidc_auth.verify_oidc_flow_token(token + "x", now=110) is None
    assert oidc_auth.verify_oidc_flow_token(token, now=131) is None


def test_authorization_url_uses_pkce_state_and_nonce(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    config = oidc_auth.configured_oidc_config()
    flow, _ = oidc_auth.new_oidc_flow("/cases")

    url = oidc_auth.build_authorization_url(config, _metadata(), flow)
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["breachscope"]
    assert query["state"] == [flow["state"]]
    assert query["nonce"] == [flow["nonce"]]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"][0]
    assert "openid" in query["scope"][0].split()


def test_role_mapping_is_exact_and_ambiguous_non_admin_is_rejected(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    monkeypatch.setenv("BS_OIDC_AUTHOR_VALUES", "breachscope-authors")
    config = oidc_auth.configured_oidc_config()

    assert (
        oidc_auth.map_claims_to_role(
            {"groups": ["breachscope-operators"]},
            config,
        )
        == "operator"
    )
    with pytest.raises(oidc_auth.OidcAuthorizationError):
        oidc_auth.map_claims_to_role(
            {"groups": ["breachscope-operators", "breachscope-authors"]},
            config,
        )


def test_admin_mapping_wins_over_other_mapped_roles(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    monkeypatch.setenv("BS_OIDC_ADMIN_VALUES", "breachscope-admins")
    monkeypatch.setenv("BS_OIDC_AUTHOR_VALUES", "breachscope-authors")
    config = oidc_auth.configured_oidc_config()

    assert oidc_auth.map_claims_to_role(
        {"groups": ["breachscope-admins", "breachscope-authors"]},
        config,
    ) == "admin"


def test_nested_role_claim_is_supported(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    monkeypatch.setenv("BS_OIDC_ROLE_CLAIM", "realm_access.roles")
    config = oidc_auth.configured_oidc_config()

    assert oidc_auth.map_claims_to_role(
        {"realm_access": {"roles": ["breachscope-operators"]}},
        config,
    ) == "operator"


def test_discovery_rejects_issuer_mismatch(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    config = oidc_auth.configured_oidc_config()
    monkeypatch.setattr(
        oidc_auth,
        "_fetch_json",
        lambda *args, **kwargs: {
            **_metadata(),
            "issuer": "https://other.example.test",
        },
    )

    with pytest.raises(oidc_auth.OidcProtocolError):
        oidc_auth.fetch_discovery(config)


def test_id_token_rejects_hmac_algorithm_before_jwks_fetch(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    config = oidc_auth.configured_oidc_config()
    token = jwt.encode(
        {
            "iss": config.issuer_url,
            "sub": "alice",
            "aud": config.client_id,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "nonce": "nonce",
        },
        "not-a-provider-key-that-is-at-least-32-bytes",
        algorithm="HS256",
    )

    with pytest.raises(oidc_auth.OidcProtocolError):
        oidc_auth.verify_id_token(
            config,
            _metadata(),
            id_token=token,
            nonce="nonce",
        )


def test_oidc_login_and_callback_issue_existing_breachscope_session(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(auth, "fetch_discovery", lambda config: _metadata())
    monkeypatch.setattr(
        auth,
        "exchange_code_for_tokens",
        lambda config, metadata, **kwargs: {"id_token": "unit-id-token"},
    )
    monkeypatch.setattr(
        auth,
        "verify_id_token",
        lambda config, metadata, **kwargs: {
            "sub": "subject-123",
            "groups": ["breachscope-operators"],
            "exp": int(time.time()) + 600,
        },
    )

    start = client.get("/api/auth/oidc/login?next=/cases", follow_redirects=False)
    assert start.status_code == 302
    location = start.headers["location"]
    state = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["state"][0]
    assert "code_challenge_method=S256" in location

    callback = client.get(
        "/api/auth/oidc/callback",
        params={"code": "code-123", "state": state},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/cases"

    status = client.get("/api/auth/status")
    body = status.json()
    assert body["authenticated"] is True
    assert body["auth_method"] == "session"
    assert body["session_authn"] == "oidc"
    assert body["session_role"] == "operator"
    assert body["session_subject"] == "oidc:subject-123"


def test_oidc_callback_rejects_state_mismatch(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(auth, "fetch_discovery", lambda config: _metadata())

    start = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 302

    callback = client.get(
        "/api/auth/oidc/callback",
        params={"code": "code-123", "state": "wrong-state"},
        follow_redirects=False,
    )
    assert callback.status_code == 401


def test_oidc_callback_denies_identity_without_role_mapping(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(auth, "fetch_discovery", lambda config: _metadata())
    monkeypatch.setattr(
        auth,
        "exchange_code_for_tokens",
        lambda config, metadata, **kwargs: {"id_token": "unit-id-token"},
    )
    monkeypatch.setattr(
        auth,
        "verify_id_token",
        lambda config, metadata, **kwargs: {
            "sub": "subject-123",
            "groups": ["some-other-group"],
            "exp": int(time.time()) + 600,
        },
    )

    start = client.get("/api/auth/oidc/login", follow_redirects=False)
    state = urllib.parse.parse_qs(
        urllib.parse.urlparse(start.headers["location"]).query
    )["state"][0]

    callback = client.get(
        "/api/auth/oidc/callback",
        params={"code": "code-123", "state": state},
        follow_redirects=False,
    )
    assert callback.status_code == 403


def test_oidc_session_is_revoked_when_role_mapping_is_removed(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(auth, "fetch_discovery", lambda config: _metadata())
    monkeypatch.setattr(
        auth,
        "exchange_code_for_tokens",
        lambda config, metadata, **kwargs: {"id_token": "unit-id-token"},
    )
    monkeypatch.setattr(
        auth,
        "verify_id_token",
        lambda config, metadata, **kwargs: {
            "sub": "subject-123",
            "groups": ["breachscope-operators"],
            "exp": int(time.time()) + 600,
        },
    )

    start = client.get("/api/auth/oidc/login", follow_redirects=False)
    state = urllib.parse.parse_qs(
        urllib.parse.urlparse(start.headers["location"]).query
    )["state"][0]
    assert client.get(
        "/api/auth/oidc/callback",
        params={"code": "code-123", "state": state},
        follow_redirects=False,
    ).status_code == 303
    assert client.get("/api/auth/status").json()["authenticated"] is True

    monkeypatch.delenv("BS_OIDC_OPERATOR_VALUES", raising=False)
    status = client.get("/api/auth/status").json()
    assert status["authenticated"] is False
    assert status["oidc_login_enabled"] is False


def test_web_template_exposes_oidc_login_and_runtime_copy_matches():
    from pathlib import Path

    source = Path("templates/web_index.html").read_text(encoding="utf-8")
    runtime = Path("breachscope/runtime_data/templates/web_index.html").read_text(encoding="utf-8")
    assert source == runtime
    assert 'id="oidcLoginBtn"' in source
    assert "/api/auth/oidc/login?next=/" in source
    assert "payload.oidc_login_enabled" in source


def test_oidc_defaults_alone_do_not_enable_auth(monkeypatch):
    for name in OIDC_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BS_OIDC_SCOPES", "openid profile email")
    monkeypatch.setenv("BS_OIDC_ROLE_CLAIM", "groups")

    assert oidc_auth.oidc_settings_present() is False
    assert oidc_auth.oidc_is_configured() is False


def test_oidc_flow_sanitizes_header_injection_next(monkeypatch, tmp_path):
    _configure_oidc(monkeypatch, tmp_path)
    token = oidc_auth.create_oidc_flow_token(
        state="state",
        nonce="nonce",
        code_verifier="verifier",
        next_path="/ok\r\nLocation: https://evil.example",
        now=100,
        ttl_seconds=30,
    )
    payload = oidc_auth.verify_oidc_flow_token(token, now=110)
    assert payload is not None
    assert payload["next"] == "/"
