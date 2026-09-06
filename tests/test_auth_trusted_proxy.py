from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import setup_middleware
from api.routers import auth


def _client(tmp_path, monkeypatch, *, trusted_proxy_ips: str | None = None) -> TestClient:
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "unit-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "unit-session-secret")
    monkeypatch.setenv("BS_AUTH_RATE_LIMIT_PATH", str(tmp_path / "auth_rate_limit.json"))
    monkeypatch.setenv("BS_AUTH_MAX_FAILURES", "2")
    monkeypatch.setenv("BS_AUTH_LOCKOUT_SECONDS", "60")
    if trusted_proxy_ips is None:
        monkeypatch.delenv("BS_TRUSTED_PROXY_IPS", raising=False)
    else:
        monkeypatch.setenv("BS_TRUSTED_PROXY_IPS", trusted_proxy_ips)

    app = FastAPI()
    setup_middleware(app)
    app.include_router(auth.router, prefix="/api")
    return TestClient(app, client=("203.0.113.10", 50000))


def test_untrusted_peer_cannot_rotate_x_forwarded_for_to_bypass_lockout(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    first = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "198.51.100.1"},
        json={"password": "bad"},
    )
    second = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "198.51.100.2"},
        json={"password": "bad"},
    )

    assert first.status_code == 401
    assert second.status_code == 429


def test_trusted_proxy_uses_forwarded_client_identity(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, trusted_proxy_ips="203.0.113.10")

    first = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "198.51.100.21"},
        json={"password": "bad"},
    )
    second_other_client = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "198.51.100.22"},
        json={"password": "bad"},
    )
    second_same_client = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "198.51.100.21"},
        json={"password": "bad"},
    )

    assert first.status_code == 401
    assert second_other_client.status_code == 401
    assert second_same_client.status_code == 429


def test_trusted_proxy_chain_walks_from_right_to_left(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        trusted_proxy_ips="203.0.113.10, 192.0.2.44",
    )

    first = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "198.51.100.30, 192.0.2.44"},
        json={"password": "bad"},
    )
    second = client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "198.51.100.30, 192.0.2.44"},
        json={"password": "bad"},
    )

    assert first.status_code == 401
    assert second.status_code == 429


def test_invalid_trusted_proxy_configuration_fails_closed(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, trusted_proxy_ips="not-an-ip")

    response = client.post(
        "/api/auth/login",
        json={"password": "bad"},
    )

    assert response.status_code == 500
