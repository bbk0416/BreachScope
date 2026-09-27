from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.services.audit_log import AuditLogService


def _configure_api_key(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BS_API_KEY", "audit-org-api-key")
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_DEFAULT_ORGANIZATION_ID", "default")
    for name in (
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
        "BS_OIDC_ISSUER_URL",
        "BS_OIDC_CLIENT_ID",
        "BS_OIDC_CLIENT_SECRET",
        "BS_OIDC_REDIRECT_URI",
        "BS_OIDC_DEFAULT_ROLE",
        "BS_OIDC_ADMIN_VALUES",
        "BS_OIDC_AUTHOR_VALUES",
        "BS_OIDC_REVIEWER_VALUES",
        "BS_OIDC_OPERATOR_VALUES",
    ):
        monkeypatch.delenv(name, raising=False)


def _headers(org: str) -> dict[str, str]:
    return {
        "x-api-key": "audit-org-api-key",
        "x-breachscope-organization": org,
    }


def _append_row(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def test_audit_service_filters_organization_and_legacy_rows(
    tmp_path: Path,
    monkeypatch,
):
    _configure_api_key(monkeypatch, tmp_path)
    path = tmp_path / "audit.jsonl"
    _append_row(
        path,
        {
            "event_id": "legacy",
            "timestamp": "2026-09-28T00:00:00Z",
            "action": "legacy.event",
            "status": "success",
        },
    )
    _append_row(
        path,
        {
            "event_id": "org-a",
            "timestamp": "2026-09-28T00:00:01Z",
            "action": "org.event",
            "status": "success",
            "organization_id": "org-a",
        },
    )
    _append_row(
        path,
        {
            "event_id": "org-b",
            "timestamp": "2026-09-28T00:00:02Z",
            "action": "org.event",
            "status": "success",
            "organization_id": "org-b",
        },
    )

    svc = AuditLogService(path=path)
    assert {row["event_id"] for row in svc.read_events(limit=10)} == {
        "legacy",
        "org-a",
        "org-b",
    }
    assert [row["event_id"] for row in svc.read_events(
        limit=10,
        organization_id="org-a",
    )] == ["org-a"]
    assert [row["event_id"] for row in svc.read_events(
        limit=10,
        organization_id="default",
    )] == ["legacy"]


def test_audit_api_list_export_and_integrity_are_organization_scoped(
    tmp_path: Path,
    monkeypatch,
):
    _configure_api_key(monkeypatch, tmp_path)
    path = tmp_path / "audit.jsonl"

    for event_id, org in (
        ("a-1", "org-a"),
        ("b-1", "org-b"),
        ("a-2", "org-a"),
    ):
        _append_row(
            path,
            {
                "event_id": event_id,
                "timestamp": f"2026-09-28T00:00:0{len(event_id)}Z",
                "action": "unit.org",
                "status": "success",
                "organization_id": org,
                "actor": "tester",
                "auth_method": "unit",
                "case_id": None,
                "target": None,
                "request": {},
                "details": {},
            },
        )

    client = TestClient(app)

    listed_a = client.get("/api/audit", headers=_headers("org-a"))
    assert listed_a.status_code == 200
    assert [row["event_id"] for row in listed_a.json()["events"]] == ["a-2", "a-1"]

    listed_b = client.get("/api/audit", headers=_headers("org-b"))
    assert listed_b.status_code == 200
    assert [row["event_id"] for row in listed_b.json()["events"]] == ["b-1"]

    exported_a = client.get(
        "/api/audit/export",
        headers=_headers("org-a"),
        params={"file_type": "jsonl"},
    )
    assert exported_a.status_code == 200
    assert '"event_id": "a-1"' in exported_a.text
    assert '"event_id": "a-2"' in exported_a.text
    assert '"event_id": "b-1"' not in exported_a.text

    csv_b = client.get(
        "/api/audit/export",
        headers=_headers("org-b"),
        params={"file_type": "csv"},
    )
    assert csv_b.status_code == 200
    assert "b-1" in csv_b.text
    assert "a-1" not in csv_b.text

    integrity_a = client.get(
        "/api/audit/integrity",
        headers=_headers("org-a"),
    )
    integrity_b = client.get(
        "/api/audit/integrity",
        headers=_headers("org-b"),
    )
    assert integrity_a.status_code == 200
    assert integrity_b.status_code == 200

    body_a = integrity_a.json()["integrity"]
    body_b = integrity_b.json()["integrity"]
    assert body_a["organization_id"] == "org-a"
    assert body_a["events"] == 2
    assert body_a["scope"] == "logical-organization-events"
    assert body_b["organization_id"] == "org-b"
    assert body_b["events"] == 1
    assert body_a["sha256"] != body_b["sha256"]


def test_audit_integrity_uses_all_organization_events_not_api_limit(
    tmp_path: Path,
    monkeypatch,
):
    _configure_api_key(monkeypatch, tmp_path)
    path = tmp_path / "audit.jsonl"

    for index in range(1005):
        _append_row(
            path,
            {
                "event_id": f"a-{index}",
                "timestamp": "2026-09-28T00:00:00Z",
                "action": "bulk",
                "status": "success",
                "organization_id": "org-a",
            },
        )
    for index in range(3):
        _append_row(
            path,
            {
                "event_id": f"b-{index}",
                "timestamp": "2026-09-28T00:00:00Z",
                "action": "bulk",
                "status": "success",
                "organization_id": "org-b",
            },
        )

    client = TestClient(app)
    integrity = client.get(
        "/api/audit/integrity",
        headers=_headers("org-a"),
    )
    assert integrity.status_code == 200
    assert integrity.json()["integrity"]["events"] == 1005


def test_other_organization_events_do_not_change_scoped_integrity(
    tmp_path: Path,
    monkeypatch,
):
    _configure_api_key(monkeypatch, tmp_path)
    monkeypatch.setenv("BS_AUDIT_CHAIN_SECRET", "audit-scope-secret")
    path = tmp_path / "audit.jsonl"

    _append_row(
        path,
        {
            "event_id": "a-1",
            "timestamp": "2026-09-28T00:00:00Z",
            "action": "unit",
            "status": "success",
            "organization_id": "org-a",
        },
    )

    svc = AuditLogService(path=path)
    before = svc.verify_organization_integrity("org-a")
    assert before["hmac_sha256"]

    _append_row(
        path,
        {
            "event_id": "b-1",
            "timestamp": "2026-09-28T00:00:01Z",
            "action": "unit",
            "status": "success",
            "organization_id": "org-b",
        },
    )

    after = svc.verify_organization_integrity("org-a")
    assert after["sha256"] == before["sha256"]
    assert after["hmac_sha256"] == before["hmac_sha256"]
    assert after["events"] == 1


def test_session_audit_scope_cannot_be_overridden_by_header(
    tmp_path: Path,
    monkeypatch,
):
    from api.security import SESSION_COOKIE_NAME, create_session_token

    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "audit-org-session-secret")
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    path = tmp_path / "audit.jsonl"

    _append_row(
        path,
        {
            "event_id": "a-1",
            "timestamp": "2026-09-28T00:00:00Z",
            "action": "unit",
            "status": "success",
            "organization_id": "org-a",
        },
    )
    _append_row(
        path,
        {
            "event_id": "b-1",
            "timestamp": "2026-09-28T00:00:01Z",
            "action": "unit",
            "status": "success",
            "organization_id": "org-b",
        },
    )

    client = TestClient(app)
    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="admin",
            role="admin",
            organization_id="org-a",
        ),
    )

    response = client.get(
        "/api/audit",
        headers={"x-breachscope-organization": "org-b"},
    )
    assert response.status_code == 200
    assert [row["event_id"] for row in response.json()["events"]] == ["a-1"]


def test_web_audit_export_uses_header_capable_fetch_and_templates_match():
    source = Path("templates/web_index.html").read_text(encoding="utf-8")
    runtime = Path(
        "breachscope/runtime_data/templates/web_index.html"
    ).read_text(encoding="utf-8")

    assert source == runtime
    assert "downloadAuditExport(fileType)" in source
    assert "authFetch('/api/audit/export?file_type='" in source
    assert "withApiKey('/api/audit/export?file_type=csv')" not in source
    assert "withApiKey('/api/audit/export?file_type=jsonl')" not in source
