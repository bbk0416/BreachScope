from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import setup_middleware


def _client() -> TestClient:
    app = FastAPI()
    setup_middleware(app)

    @app.get("/api/probe")
    async def probe():
        return {"ok": True}

    return TestClient(app)


def _preflight(client: TestClient, origin: str):
    return client.options(
        "/api/probe",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-API-Key",
        },
    )


def _enable_auth(monkeypatch) -> None:
    monkeypatch.setenv("BS_API_KEY", "cors-test-secret")
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)


def test_blank_allowlist_denies_cross_origin(monkeypatch) -> None:
    _enable_auth(monkeypatch)
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "production")
    monkeypatch.delenv("BS_ALLOWED_ORIGINS", raising=False)

    response = _preflight(_client(), "https://evil.example")

    assert response.status_code != 200
    assert response.headers.get("access-control-allow-origin") is None


def test_configured_origin_allowlist_is_exact(monkeypatch) -> None:
    _enable_auth(monkeypatch)
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "production")
    monkeypatch.setenv(
        "BS_ALLOWED_ORIGINS",
        "https://console.example.com, https://soc.example.com",
    )

    client = _client()
    allowed = _preflight(client, "https://console.example.com")
    denied = _preflight(client, "https://evil.example")

    assert allowed.status_code == 200
    assert (
        allowed.headers.get("access-control-allow-origin")
        == "https://console.example.com"
    )
    assert allowed.headers.get("access-control-allow-credentials") == "true"
    assert denied.status_code != 200
    assert denied.headers.get("access-control-allow-origin") is None


def test_same_origin_behavior_does_not_require_cors_allowlist(monkeypatch) -> None:
    _enable_auth(monkeypatch)
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "local")
    monkeypatch.delenv("BS_ALLOWED_ORIGINS", raising=False)

    client = _client()
    response = client.get(
        "/api/probe",
        headers={"X-API-Key": "cors-test-secret"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_wildcard_allowed_origins_is_rejected(monkeypatch) -> None:
    _enable_auth(monkeypatch)
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "production")
    monkeypatch.setenv("BS_ALLOWED_ORIGINS", "*")

    with pytest.raises(ValueError, match=r"BS_ALLOWED_ORIGINS must not contain"):
        _client()
