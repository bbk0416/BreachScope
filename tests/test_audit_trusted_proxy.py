from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from api.services.audit_log import AuditLogService


def _client(
    tmp_path,
    monkeypatch,
    *,
    trusted_proxy_ips: str | None = None,
    raise_server_exceptions: bool = True,
) -> TestClient:
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    if trusted_proxy_ips is None:
        monkeypatch.delenv("BS_TRUSTED_PROXY_IPS", raising=False)
    else:
        monkeypatch.setenv("BS_TRUSTED_PROXY_IPS", trusted_proxy_ips)

    audit_path = tmp_path / "audit.jsonl"
    app = FastAPI()

    @app.get("/audit")
    async def write_audit(request: Request):
        return AuditLogService(path=audit_path).record("test.audit", request=request)

    return TestClient(
        app,
        client=("203.0.113.10", 50000),
        raise_server_exceptions=raise_server_exceptions,
    )


def test_audit_ignores_forwarded_for_from_untrusted_peer(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.get(
        "/audit",
        headers={"X-Forwarded-For": "198.51.100.1"},
    )

    assert response.status_code == 200
    assert response.json()["request"]["ip"] == "203.0.113.10"


def test_audit_uses_forwarded_client_from_trusted_proxy(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, trusted_proxy_ips="203.0.113.10")

    response = client.get(
        "/audit",
        headers={"X-Forwarded-For": "198.51.100.21"},
    )

    assert response.status_code == 200
    assert response.json()["request"]["ip"] == "198.51.100.21"


def test_audit_walks_trusted_proxy_chain_from_right_to_left(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        trusted_proxy_ips="203.0.113.10, 192.0.2.44",
    )

    response = client.get(
        "/audit",
        headers={"X-Forwarded-For": "198.51.100.30, 192.0.2.44"},
    )

    assert response.status_code == 200
    assert response.json()["request"]["ip"] == "198.51.100.30"


def test_audit_malformed_forwarded_hop_falls_back_to_direct_proxy(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, trusted_proxy_ips="203.0.113.10")

    response = client.get(
        "/audit",
        headers={"X-Forwarded-For": "not-an-ip"},
    )

    assert response.status_code == 200
    assert response.json()["request"]["ip"] == "203.0.113.10"


def test_audit_invalid_trusted_proxy_configuration_fails_closed(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        trusted_proxy_ips="not-an-ip",
        raise_server_exceptions=False,
    )

    response = client.get("/audit")

    assert response.status_code == 500
