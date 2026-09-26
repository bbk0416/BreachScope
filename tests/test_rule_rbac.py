from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.rule_authoring import RuleAuthoringService


def _configure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("BS_AUTHOR_PASSWORD", "author-password")
    monkeypatch.setenv("BS_REVIEWER_PASSWORD", "reviewer-password")
    monkeypatch.setenv("BS_OPERATOR_PASSWORD", "operator-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "rbac-session-secret")
    monkeypatch.setenv(
        "BS_AUTH_RATE_LIMIT_PATH", str(tmp_path / "auth_rate_limit.json")
    )
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    monkeypatch.setenv(
        "BS_RULE_AUTHORING_ROOT", str(tmp_path / "rule_authoring")
    )
    monkeypatch.setenv(
        "BS_RULE_ACTIVATION_PATH", str(tmp_path / "rule_activation.json")
    )
    monkeypatch.setenv(
        "BS_RULE_TUNING_PATH", str(tmp_path / "rule_tuning_profiles.json")
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path))


def _client_for_role(
    tmp_path: Path,
    monkeypatch,
    role: str,
) -> TestClient:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)
    password = {
        "admin": "admin-password",
        "author": "author-password",
        "reviewer": "reviewer-password",
        "operator": "operator-password",
    }[role]
    response = client.post(
        "/api/auth/login",
        json={"username": role, "password": password},
    )
    assert response.status_code == 200, response.text
    assert response.json()["session_role"] == role
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    assert status.json()["session_role"] == role
    assert status.json()["rbac_enabled"] is True
    return client


def _rule(
    rule_id: str = "C-RBAC-TEST",
    pattern: str = "rbac-custom-marker-128374",
) -> dict:
    return {
        "id": rule_id,
        "name": "RBAC custom rule",
        "description": "role boundary test",
        "field": "command_line",
        "pattern": pattern,
        "operator": "contains",
        "severity": "high",
        "mitre_technique": "T1059.001",
    }


def test_author_reviewer_operator_rule_lifecycle(tmp_path: Path, monkeypatch) -> None:
    author = _client_for_role(tmp_path, monkeypatch, "author")

    create = author.post(
        "/api/rules/authoring/drafts",
        json={"rule": _rule()},
    )
    assert create.status_code == 200
    draft = create.json()["draft"]
    assert draft["updated_by"] == "author"

    validate = author.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/validate",
        json={"expected_version": 1},
    )
    assert validate.status_code == 200

    forbidden_approve = author.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/approve",
        json={
            "expected_version": 1,
            "review_note": "author must not approve",
        },
    )
    assert forbidden_approve.status_code == 403

    reviewer = _client_for_role(tmp_path, monkeypatch, "reviewer")
    forbidden_create = reviewer.post(
        "/api/rules/authoring/drafts",
        json={"rule": _rule("C-REVIEWER-CANNOT-AUTHOR")},
    )
    assert forbidden_create.status_code == 403

    approve = reviewer.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/approve",
        json={
            "expected_version": 1,
            "review_note": "separate reviewer approval",
        },
    )
    assert approve.status_code == 200
    assert approve.json()["draft"]["approval"]["approved_by"] == "reviewer"

    publish = reviewer.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/publish",
        json={"expected_version": 1},
    )
    assert publish.status_code == 200

    forbidden_activate = reviewer.post(
        "/api/rules/activation/activate",
        json={
            "expected_version": 0,
            "draft_id": draft["draft_id"],
            "published_version": 1,
        },
    )
    assert forbidden_activate.status_code == 403

    operator = _client_for_role(tmp_path, monkeypatch, "operator")
    forbidden_author = operator.post(
        "/api/rules/authoring/drafts",
        json={"rule": _rule("C-OPERATOR-CANNOT-AUTHOR")},
    )
    assert forbidden_author.status_code == 403

    activate = operator.post(
        "/api/rules/activation/activate",
        json={
            "expected_version": 0,
            "draft_id": draft["draft_id"],
            "published_version": 1,
        },
    )
    assert activate.status_code == 200
    assert activate.json()["activation"]["active"][0]["rule_id"] == "C-RBAC-TEST"


def test_custom_rule_analysis_requires_operator_or_admin(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    authoring = RuleAuthoringService(
        root=tmp_path / "rule_authoring",
        canonical_rules_dir=Path("rules"),
    )
    draft = authoring.create_draft(rule=_rule("C-RBAC-ANALYSIS"), updated_by="author")
    authoring.validate_draft(draft["draft_id"], expected_version=1)
    authoring.approve_draft(
        draft["draft_id"],
        expected_version=1,
        review_note="reviewed",
        approved_by="reviewer",
        require_distinct_reviewer=True,
    )
    published = authoring.publish_draft(
        draft["draft_id"],
        expected_version=1,
        published_by="reviewer",
    )

    operator = _client_for_role(tmp_path, monkeypatch, "operator")
    activate = operator.post(
        "/api/rules/activation/activate",
        json={
            "expected_version": 0,
            "draft_id": draft["draft_id"],
            "published_version": published["publications"][-1]["version"],
        },
    )
    assert activate.status_code == 200

    event = {
        "timestamp": "2026-09-26T12:00:00Z",
        "host": "WS-RBAC",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\analyst",
        "command_line": "rbac-custom-marker-128374",
    }
    sample = tmp_path / "rbac-events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    author = _client_for_role(tmp_path, monkeypatch, "author")
    with sample.open("rb") as handle:
        denied = author.post(
            "/api/analyze",
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "true",
                "use_custom_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "author-work"),
            },
        )
    assert denied.status_code == 403

    with sample.open("rb") as handle:
        allowed = operator.post(
            "/api/analyze",
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "true",
                "use_custom_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "operator-work"),
            },
        )
    assert allowed.status_code == 200
    assert allowed.json()["count"] == 1
    assert allowed.json()["custom_rule_activation"][
        "effective_custom_rule_ids"
    ] == ["C-RBAC-ANALYSIS"]


def test_reviewer_cannot_approve_own_current_version(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    service = RuleAuthoringService(
        root=tmp_path / "rule_authoring",
        canonical_rules_dir=Path("rules"),
    )
    draft = service.create_draft(
        rule=_rule("C-RBAC-SELF-APPROVE"),
        updated_by="reviewer",
    )
    service.validate_draft(draft["draft_id"], expected_version=1)

    reviewer = _client_for_role(tmp_path, monkeypatch, "reviewer")
    response = reviewer.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/approve",
        json={
            "expected_version": 1,
            "review_note": "must be rejected",
        },
    )
    assert response.status_code == 409
    assert "작성/수정한 주체" in response.json()["detail"]


def test_admin_can_override_all_rule_roles(tmp_path: Path, monkeypatch) -> None:
    admin = _client_for_role(tmp_path, monkeypatch, "admin")

    create = admin.post(
        "/api/rules/authoring/drafts",
        json={"rule": _rule("C-RBAC-ADMIN")},
    )
    assert create.status_code == 200
    draft = create.json()["draft"]

    assert (
        admin.post(
            f"/api/rules/authoring/drafts/{draft['draft_id']}/validate",
            json={"expected_version": 1},
        ).status_code
        == 200
    )
    approve = admin.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/approve",
        json={
            "expected_version": 1,
            "review_note": "admin emergency override",
        },
    )
    assert approve.status_code == 200
    assert approve.json()["draft"]["approval"]["approved_by"] == "admin"

    assert (
        admin.post(
            f"/api/rules/authoring/drafts/{draft['draft_id']}/publish",
            json={"expected_version": 1},
        ).status_code
        == 200
    )
    assert (
        admin.post(
            "/api/rules/activation/activate",
            json={
                "expected_version": 0,
                "draft_id": draft["draft_id"],
                "published_version": 1,
            },
        ).status_code
        == 200
    )


def test_unknown_username_still_cannot_choose_session_subject(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)
    response = client.post(
        "/api/auth/login",
        json={"username": "invented-admin", "password": "admin-password"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["session_subject"] == "admin"
    assert body["session_role"] == "admin"

    status = client.get("/api/auth/status").json()
    assert status["session_subject"] == "admin"
    assert status["session_role"] == "admin"
    assert status["configured_roles"] == ["author", "operator", "reviewer"]


def test_role_only_password_enables_auth_without_admin_or_api_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("BS_REVIEWER_PASSWORD", raising=False)
    monkeypatch.delenv("BS_OPERATOR_PASSWORD", raising=False)
    monkeypatch.setenv("BS_AUTHOR_PASSWORD", "author-only-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "role-only-session-secret-1234567890")
    monkeypatch.setenv(
        "BS_AUTH_RATE_LIMIT_PATH", str(tmp_path / "auth_rate_limit.json")
    )

    client = TestClient(app)
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    payload = status.json()
    assert payload["auth_required"] is True
    assert payload["password_login_enabled"] is True
    assert payload["rbac_enabled"] is True
    assert payload["configured_roles"] == ["author"]
    assert payload["authenticated"] is False

    assert client.get("/api/cases").status_code == 401

    admin_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "author-only-password"},
    )
    assert admin_login.status_code == 400

    author_login = client.post(
        "/api/auth/login",
        json={"username": "author", "password": "author-only-password"},
    )
    assert author_login.status_code == 200
    assert author_login.json()["session_subject"] == "author"
    assert author_login.json()["session_role"] == "author"


def test_web_ui_exposes_role_login_and_permission_hints() -> None:
    response = TestClient(app).get("/")
    assert response.status_code == 200
    body = response.text
    assert 'id="loginRole"' in body
    assert '<option value="author">author</option>' in body
    assert '<option value="reviewer">reviewer</option>' in body
    assert '<option value="operator">operator</option>' in body
    assert "function roleAllows(...roles)" in body
    assert "currentAuthRole === 'admin'" in body
    assert "customToggle.disabled = !canOperate" in body
    assert "JSON.stringify({username: loginRole.value, password})" in body


def test_known_unconfigured_role_does_not_fall_back_to_admin(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("BS_AUTHOR_PASSWORD", "author-password")
    monkeypatch.delenv("BS_REVIEWER_PASSWORD", raising=False)
    monkeypatch.delenv("BS_OPERATOR_PASSWORD", raising=False)
    monkeypatch.setenv("BS_SESSION_SECRET", "rbac-session-secret")
    monkeypatch.setenv(
        "BS_AUTH_RATE_LIMIT_PATH", str(tmp_path / "auth_rate_limit.json")
    )

    client = TestClient(app)
    response = client.post(
        "/api/auth/login",
        json={"username": "reviewer", "password": "admin-password"},
    )
    assert response.status_code == 400
    assert "reviewer" in response.json()["detail"]


def test_unknown_signed_session_role_is_not_promoted_to_admin(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)
    token = create_session_token(subject="rogue", role="rogue")
    client.cookies.set(SESSION_COOKIE_NAME, token)

    response = client.post(
        "/api/rules/authoring/drafts",
        json={"rule": _rule("C-RBAC-ROGUE")},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"
    assert "Authentication is required" in response.json()["message"]


def test_removed_role_password_revokes_existing_role_session(
    tmp_path: Path,
    monkeypatch,
) -> None:
    author = _client_for_role(tmp_path, monkeypatch, "author")
    assert author.get("/api/cases").status_code == 200

    monkeypatch.delenv("BS_AUTHOR_PASSWORD", raising=False)

    status = author.get("/api/auth/status")
    assert status.status_code == 200
    payload = status.json()
    assert payload["authenticated"] is False
    assert payload["session_subject"] is None
    assert payload["session_role"] is None
    assert "author" not in payload["configured_roles"]

    assert author.get("/api/cases").status_code == 401
