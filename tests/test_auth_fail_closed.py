from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import setup_middleware


def _app(monkeypatch, *, deployment="local", api_key=None, admin_password=None):
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", deployment)

    if api_key is None:
        monkeypatch.delenv("BS_API_KEY", raising=False)
    else:
        monkeypatch.setenv("BS_API_KEY", api_key)

    if admin_password is None:
        monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("BS_ADMIN_PASSWORD", admin_password)

    app = FastAPI()
    setup_middleware(app)

    @app.get("/api/cases")
    async def cases():
        return {"ok": True}

    @app.get("/api/health/live")
    async def live():
        return {"status": "live"}

    @app.get("/api/auth/status")
    async def auth_status():
        return {"status": "auth"}

    return TestClient(app)


def test_local_mode_without_credentials_remains_demo_compatible(monkeypatch):
    client = _app(monkeypatch, deployment="local")
    assert client.get("/api/cases").status_code == 200


def test_production_without_credentials_fails_closed(monkeypatch):
    client = _app(monkeypatch, deployment="production")
    response = client.get("/api/cases")
    assert response.status_code == 503
    assert response.json()["code"] == "AUTH_MISCONFIGURED"


def test_production_without_credentials_keeps_probe_and_auth_status_public(monkeypatch):
    client = _app(monkeypatch, deployment="production")
    assert client.get("/api/health/live").status_code == 200
    assert client.get("/api/auth/status").status_code == 200


def test_production_with_api_key_accepts_x_api_key(monkeypatch):
    client = _app(monkeypatch, deployment="production", api_key="unit-secret")
    assert client.get(
        "/api/cases",
        headers={"X-API-Key": "unit-secret"},
    ).status_code == 200


def test_production_with_api_key_accepts_bearer(monkeypatch):
    client = _app(monkeypatch, deployment="production", api_key="unit-secret")
    assert client.get(
        "/api/cases",
        headers={"Authorization": "Bearer unit-secret"},
    ).status_code == 200


def test_query_string_api_key_is_rejected(monkeypatch):
    client = _app(monkeypatch, deployment="local", api_key="unit-secret")
    assert client.get("/api/cases?api_key=unit-secret").status_code == 401


def test_extract_api_key_ignores_query_string():
    from starlette.requests import Request
    from api.security import extract_api_key

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/cases",
        "query_string": b"api_key=unit-secret",
        "headers": [],
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "scheme": "http",
        "root_path": "",
        "http_version": "1.1",
    }
    assert extract_api_key(Request(scope)) == ""


def test_auth_is_enabled_in_production_even_when_credentials_missing(monkeypatch):
    from api.security import auth_is_enabled

    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "production")
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)

    assert auth_is_enabled() is True


def test_p0_12_marker_present():
    import api.security as security

    source = open(security.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P0_12_AUTH_FAIL_CLOSED_V1" in source
    assert 'request.query_params.get("api_key"' not in source
