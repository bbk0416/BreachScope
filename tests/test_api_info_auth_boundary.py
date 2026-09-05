from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app


def _enable_api_key(monkeypatch) -> None:
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "production")
    monkeypatch.setenv("BS_API_KEY", "info-boundary-secret")
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)


def test_api_info_requires_auth_when_auth_is_enabled(monkeypatch) -> None:
    _enable_api_key(monkeypatch)
    client = TestClient(app)

    response = client.get("/api/info")
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_api_info_remains_available_to_authenticated_operator(monkeypatch) -> None:
    _enable_api_key(monkeypatch)
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", r"C:\private\case_history.json")
    monkeypatch.setenv("BS_CASES_ROOT", r"C:\private\cases")
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", r"C:\private\audit.jsonl")
    monkeypatch.setenv("BS_BACKUP_ROOT", r"C:\private\backups")

    client = TestClient(app)
    response = client.get(
        "/api/info",
        headers={"X-API-Key": "info-boundary-secret"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["case_history_path"] == r"C:\private\case_history.json"
    assert payload["cases_root"] == r"C:\private\cases"
    assert payload["audit_log_path"] == r"C:\private\audit.jsonl"
    assert payload["backup_root"] == r"C:\private\backups"


def test_health_remains_public_when_auth_is_enabled(monkeypatch) -> None:
    _enable_api_key(monkeypatch)
    client = TestClient(app)

    response = client.get("/api/health")
    assert response.status_code == 200


def test_local_no_auth_api_info_compatibility_is_preserved(monkeypatch) -> None:
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "local")
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)

    client = TestClient(app)
    response = client.get("/api/info")

    assert response.status_code == 200
    assert response.json()["name"] == "BreachScope"
