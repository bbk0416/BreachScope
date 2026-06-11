"""Optional API-key middleware tests."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import setup_middleware


def _secure_app(monkeypatch):
    monkeypatch.setenv("BS_API_KEY", "unit-secret")
    app = FastAPI()
    setup_middleware(app)

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/cases")
    async def cases():
        return {"success": True}

    return TestClient(app)


def test_api_key_middleware_blocks_protected_api_without_key(monkeypatch):
    client = _secure_app(monkeypatch)

    assert client.get("/api/health").status_code == 200
    response = client.get("/api/cases")

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_api_key_middleware_accepts_header_bearer_and_query(monkeypatch):
    client = _secure_app(monkeypatch)

    assert client.get("/api/cases", headers={"X-API-Key": "unit-secret"}).status_code == 200
    assert client.get("/api/cases", headers={"Authorization": "Bearer unit-secret"}).status_code == 200
    assert client.get("/api/cases?api_key=unit-secret").status_code == 200
    assert client.get("/api/cases", headers={"X-API-Key": "wrong"}).status_code == 401


def _password_app(monkeypatch):
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "unit-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "unit-session-secret")

    from api.routers import auth

    app = FastAPI()
    setup_middleware(app)
    app.include_router(auth.router, prefix="/api")

    @app.get("/api/cases")
    async def cases():
        return {"success": True}

    return TestClient(app)


def test_password_login_creates_http_only_session(monkeypatch):
    client = _password_app(monkeypatch)

    status = client.get("/api/auth/status")
    assert status.status_code == 200
    assert status.json()["auth_required"] is True
    assert status.json()["password_login_enabled"] is True
    assert status.json()["authenticated"] is False

    assert client.get("/api/cases").status_code == 401
    assert client.post("/api/auth/login", json={"password": "wrong"}).status_code == 401

    login = client.post("/api/auth/login", json={"password": "unit-password"})
    assert login.status_code == 200
    assert "httponly" in login.headers.get("set-cookie", "").lower()
    assert client.get("/api/cases").status_code == 200

    status = client.get("/api/auth/status").json()
    assert status["authenticated"] is True
    assert status["auth_method"] == "session"

    logout = client.post("/api/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/cases").status_code == 401


def test_session_token_signature_and_expiry(monkeypatch):
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "unit-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "unit-session-secret")
    from api.security import create_session_token, verify_session_token

    token = create_session_token(subject="admin", ttl_seconds=10, now=100)
    assert verify_session_token(token, now=105)["sub"] == "admin"
    assert verify_session_token(token, now=111) is None
    assert verify_session_token(token + "tampered", now=105) is None


def test_password_login_lockout_after_repeated_failures(tmp_path, monkeypatch):
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "unit-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "unit-session-secret")
    monkeypatch.setenv("BS_AUTH_RATE_LIMIT_PATH", str(tmp_path / "auth_rate_limit.json"))
    monkeypatch.setenv("BS_AUTH_MAX_FAILURES", "2")
    monkeypatch.setenv("BS_AUTH_LOCKOUT_SECONDS", "60")

    from api.routers import auth

    app = FastAPI()
    setup_middleware(app)
    app.include_router(auth.router, prefix="/api")
    client = TestClient(app)

    assert client.post("/api/auth/login", json={"password": "bad"}).status_code == 401
    locked = client.post("/api/auth/login", json={"password": "bad"})
    assert locked.status_code == 429
    still_locked = client.post("/api/auth/login", json={"password": "unit-password"})
    assert still_locked.status_code == 429
