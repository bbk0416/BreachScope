from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import setup_middleware
from api.routers import auth


def _client(tmp_path, monkeypatch, *, max_failures: int = 2) -> TestClient:
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "unit-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "unit-session-secret")
    monkeypatch.setenv("BS_AUTH_RATE_LIMIT_PATH", str(tmp_path / "auth_rate_limit.json"))
    monkeypatch.setenv("BS_AUTH_MAX_FAILURES", str(max_failures))
    monkeypatch.setenv("BS_AUTH_LOCKOUT_SECONDS", "60")
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))

    app = FastAPI()
    setup_middleware(app)
    app.include_router(auth.router, prefix="/api")
    return TestClient(app)


def test_rotating_supplied_username_cannot_bypass_admin_lockout(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, max_failures=2)

    first = client.post(
        "/api/auth/login",
        json={"password": "bad", "username": "alice"},
    )
    second = client.post(
        "/api/auth/login",
        json={"password": "bad", "username": "bob"},
    )

    assert first.status_code == 401
    assert second.status_code == 429


def test_supplied_username_cannot_change_session_subject_or_audit_actor(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    login = client.post(
        "/api/auth/login",
        json={"password": "unit-password", "username": "alice"},
    )

    assert login.status_code == 200

    status = client.get("/api/auth/status")
    assert status.status_code == 200
    assert status.json()["authenticated"] is True
    assert status.json()["session_subject"] == "admin"

    audit_path = tmp_path / "audit.jsonl"
    entries = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    success = [
        entry
        for entry in entries
        if entry.get("action") == "auth.login" and entry.get("status") == "success"
    ]

    assert len(success) == 1
    assert success[0]["actor"] == "admin"
    assert success[0]["auth_method"] == "session"
    assert success[0]["details"]["username"] == "admin"
    assert "alice" not in json.dumps(success[0], ensure_ascii=False)
