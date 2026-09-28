from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.rbac import (
    OrganizationRbacPolicyError,
    configured_organization_rbac_policies,
    effective_role_permissions,
    organization_rbac_policy_settings_present,
)
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.rule_activation import RuleActivationService
from api.services.rule_authoring import RuleAuthoringService


ORG_A_KEY = "a" * 32
GLOBAL_KEY = "g" * 32


def _clear_auth(monkeypatch) -> None:
    for name in (
        "BS_API_KEY",
        "BS_ORGANIZATION_API_KEYS",
        "BS_ORGANIZATION_RBAC_POLICIES",
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


def _configure(tmp_path: Path, monkeypatch) -> None:
    _clear_auth(monkeypatch)
    monkeypatch.setenv(
        "BS_SESSION_SECRET",
        "organization-rbac-session-secret-1234567890",
    )
    monkeypatch.setenv(
        "BS_RULE_TUNING_PATH",
        str(tmp_path / "rule_tuning_profiles.json"),
    )
    monkeypatch.setenv(
        "BS_RULE_AUTHORING_ROOT",
        str(tmp_path / "rule_authoring"),
    )
    monkeypatch.setenv(
        "BS_RULE_ACTIVATION_PATH",
        str(tmp_path / "rule_activation.json"),
    )
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )


def _session_client(
    *,
    role: str,
    organization_id: str,
) -> TestClient:
    client = TestClient(app)
    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject=role,
            role=role,
            organization_id=organization_id,
        ),
    )
    return client


def _rule(rule_id: str, pattern: str) -> dict:
    return {
        "id": rule_id,
        "name": "Organization RBAC rule",
        "description": "organization-specific permission test",
        "field": "command_line",
        "pattern": pattern,
        "operator": "contains",
        "severity": "high",
        "mitre_technique": "T1059.001",
    }


def _publish(
    organization_id: str,
    *,
    rule_id: str,
    pattern: str,
) -> dict:
    authoring = RuleAuthoringService(
        organization_id=organization_id,
        canonical_rules_dir=Path("rules"),
    )
    draft = authoring.create_draft(
        rule=_rule(rule_id, pattern),
        updated_by="fixture-author",
    )
    authoring.validate_draft(
        draft["draft_id"],
        expected_version=1,
    )
    authoring.approve_draft(
        draft["draft_id"],
        expected_version=1,
        review_note="fixture approval",
        approved_by="fixture-reviewer",
    )
    return authoring.publish_draft(
        draft["draft_id"],
        expected_version=1,
        published_by="fixture-reviewer",
    )


def _activate_direct(
    organization_id: str,
    draft: dict,
) -> None:
    publication = draft["publications"][-1]
    RuleActivationService(
        organization_id=organization_id,
    ).activate(
        draft_id=draft["draft_id"],
        published_version=publication["version"],
        expected_version=0,
        actor="fixture-operator",
    )


def test_organization_rbac_policy_parser_and_defaults() -> None:
    env = {
        "BS_ORGANIZATION_RBAC_POLICIES": json.dumps(
            {
                "Org-A": {
                    "operator": ["analysis.custom_rules"],
                    "author": [],
                }
            }
        )
    }
    policies = configured_organization_rbac_policies(env)
    assert policies["org-a"]["operator"] == frozenset(
        {"analysis.custom_rules"}
    )
    assert policies["org-a"]["author"] == frozenset()
    assert effective_role_permissions(
        "org-a",
        "operator",
        env,
    ) == frozenset({"analysis.custom_rules"})
    assert effective_role_permissions(
        "org-a",
        "reviewer",
        env,
    ) == frozenset({"rule.review"})

    assert organization_rbac_policy_settings_present(
        {"BS_ORGANIZATION_RBAC_POLICIES": "{}"}
    ) is False


@pytest.mark.parametrize(
    "raw",
    [
        "{bad-json",
        "[]",
        '{"org-a":{"unknown":["rule.author"]}}',
        '{"org-a":{"operator":["unknown.permission"]}}',
        '{"org-a":{"operator":"rule.operate"}}',
        (
            '{"Org-A":{"operator":["rule.operate"]},'
            '"org-a":{"operator":["analysis.custom_rules"]}}'
        ),
        (
            '{"org-a":{"Operator":["rule.operate"],'
            '"operator":["analysis.custom_rules"]}}'
        ),
    ],
)
def test_invalid_organization_rbac_policy_is_rejected(raw: str) -> None:
    with pytest.raises(OrganizationRbacPolicyError):
        configured_organization_rbac_policies(
            {"BS_ORGANIZATION_RBAC_POLICIES": raw}
        )


def test_same_operator_role_has_different_permissions_by_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv(
        "BS_OPERATOR_PASSWORD",
        "operator-password-12345",
    )
    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        json.dumps(
            {
                "org-a": {
                    "operator": ["analysis.custom_rules"],
                },
                "org-b": {
                    "operator": ["rule.operate"],
                },
            }
        ),
    )

    marker = "org-rbac-analysis-marker-739102"
    published_a = _publish(
        "org-a",
        rule_id="C-ORG-RBAC-A",
        pattern=marker,
    )
    _activate_direct("org-a", published_a)

    published_b = _publish(
        "org-b",
        rule_id="C-ORG-RBAC-B",
        pattern="org-b-activation-marker",
    )

    event = {
        "timestamp": "2026-09-28T05:00:00Z",
        "host": "WS-ORG-RBAC",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\analyst",
        "command_line": marker,
    }
    sample = tmp_path / "events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    org_a = _session_client(
        role="operator",
        organization_id="org-a",
    )
    status_a = org_a.get("/api/auth/status").json()
    assert status_a["active_permissions"] == [
        "analysis.custom_rules"
    ]
    assert status_a["organization_rbac_policy_config_valid"] is True

    with sample.open("rb") as handle:
        analysis_a = org_a.post(
            "/api/analyze",
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "false",
                "use_custom_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "cases" / "org-a-analysis"),
            },
        )
    assert analysis_a.status_code == 200, analysis_a.text
    assert analysis_a.json()["custom_rule_activation"][
        "effective_custom_rule_ids"
    ] == ["C-ORG-RBAC-A"]

    denied_activation = org_a.post(
        "/api/rules/activation/activate",
        json={
            "expected_version": 1,
            "draft_id": published_a["draft_id"],
            "published_version": 1,
        },
    )
    assert denied_activation.status_code == 403
    assert "rule.operate" in denied_activation.json()["detail"]

    org_b = _session_client(
        role="operator",
        organization_id="org-b",
    )
    status_b = org_b.get("/api/auth/status").json()
    assert status_b["active_permissions"] == ["rule.operate"]

    with sample.open("rb") as handle:
        denied_analysis = org_b.post(
            "/api/analyze",
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "false",
                "use_custom_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "cases" / "org-b-analysis"),
            },
        )
    assert denied_analysis.status_code == 403
    assert "analysis.custom_rules" in denied_analysis.json()["detail"]

    activated_b = org_b.post(
        "/api/rules/activation/activate",
        json={
            "expected_version": 0,
            "draft_id": published_b["draft_id"],
            "published_version": 1,
        },
    )
    assert activated_b.status_code == 200, activated_b.text


def test_author_permission_can_be_disabled_per_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv(
        "BS_AUTHOR_PASSWORD",
        "author-password-12345",
    )
    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        json.dumps(
            {
                "org-a": {"author": []},
                "org-b": {"author": ["rule.author"]},
            }
        ),
    )

    org_a = _session_client(role="author", organization_id="org-a")
    denied = org_a.post(
        "/api/rules/profiles",
        json={
            "name": "Denied profile",
            "rule_include": ["R-ENC"],
            "rule_exclude": [],
        },
    )
    assert denied.status_code == 403
    assert "rule.author" in denied.json()["detail"]

    org_b = _session_client(role="author", organization_id="org-b")
    allowed = org_b.post(
        "/api/rules/profiles",
        json={
            "name": "Allowed profile",
            "rule_include": ["R-ENC"],
            "rule_exclude": [],
        },
    )
    assert allowed.status_code == 200, allowed.text


def test_organization_bound_admin_key_obeys_policy_but_global_key_bypasses(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("BS_API_KEY", GLOBAL_KEY)
    monkeypatch.setenv(
        "BS_ORGANIZATION_API_KEYS",
        json.dumps({"org-a": ORG_A_KEY}),
    )
    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        json.dumps(
            {
                "org-a": {
                    "admin": ["analysis.custom_rules"],
                }
            }
        ),
    )

    client = TestClient(app)
    denied = client.post(
        "/api/rules/profiles",
        headers={"x-api-key": ORG_A_KEY},
        json={
            "name": "Delegated denied",
            "rule_include": ["R-ENC"],
            "rule_exclude": [],
        },
    )
    assert denied.status_code == 403
    assert "rule.author" in denied.json()["detail"]

    status = client.get(
        "/api/auth/status",
        headers={"x-api-key": ORG_A_KEY},
    ).json()
    assert status["api_key_delegated"] is True
    assert status["active_permissions"] == [
        "analysis.custom_rules"
    ]

    allowed = client.post(
        "/api/rules/profiles",
        headers={
            "x-api-key": GLOBAL_KEY,
            "x-breachscope-organization": "org-a",
        },
        json={
            "name": "Global override",
            "rule_include": ["R-ENC"],
            "rule_exclude": [],
        },
    )
    assert allowed.status_code == 200, allowed.text

    global_status = client.get(
        "/api/auth/status",
        headers={
            "x-api-key": GLOBAL_KEY,
            "x-breachscope-organization": "org-a",
        },
    ).json()
    assert global_status["api_key_delegated"] is False
    assert global_status["active_permissions"] == ["*"]


def test_object_storage_permission_is_separate_from_rule_operation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv(
        "BS_OPERATOR_PASSWORD",
        "operator-password-12345",
    )
    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        json.dumps(
            {
                "org-a": {
                    "operator": ["rule.operate"],
                }
            }
        ),
    )

    client = _session_client(
        role="operator",
        organization_id="org-a",
    )
    denied = client.post(
        "/api/cases/not-a-real-case/object-storage/replicate"
    )
    assert denied.status_code == 403
    assert "case.object_storage" in denied.json()["detail"]


def test_malformed_policy_fails_role_gated_request_and_status(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv(
        "BS_OPERATOR_PASSWORD",
        "operator-password-12345",
    )
    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        "{bad-json",
    )

    client = _session_client(
        role="operator",
        organization_id="org-a",
    )
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    body = status.json()
    assert body["organization_rbac_policy_settings_present"] is True
    assert body["organization_rbac_policy_config_valid"] is False
    assert body["active_permissions"] == []

    denied = client.post(
        "/api/rules/activation/activate",
        json={
            "expected_version": 0,
            "draft_id": "missing",
            "published_version": 1,
        },
    )
    assert denied.status_code == 503
    assert "RBAC policy configuration" in denied.json()["detail"]


def test_web_ui_uses_effective_permissions_and_templates_match() -> None:
    source = Path("templates/web_index.html").read_text(encoding="utf-8")
    runtime = Path(
        "breachscope/runtime_data/templates/web_index.html"
    ).read_text(encoding="utf-8")

    assert source == runtime
    assert "currentAuthPermissions" in source
    assert "permissionAllows('rule.author')" in source
    assert "permissionAllows('rule.review')" in source
    assert "permissionAllows('rule.operate')" in source
    assert "permissionAllows('analysis.custom_rules')" in source
    assert "permissionAllows('case.object_storage')" in source
