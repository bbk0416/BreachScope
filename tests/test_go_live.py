from pathlib import Path
import json
import os

from fastapi.testclient import TestClient

from api.main import app
from api.services.scim_directory import (
    BREACHSCOPE_GROUP_SCHEMA,
    BREACHSCOPE_USER_SCHEMA,
    ScimUserDirectory,
)
from api.services.scim_groups import ScimGroupDirectory
from breachscope.bootstrap_env import generate_env_text, write_env_file
from breachscope.golive import render_markdown, run_go_live_check

client = TestClient(app)


def _good_env(tmp_path: Path) -> dict[str, str]:
    return {
        "BS_DEPLOYMENT_MODE": "production",
        "BS_API_KEY": "a" * 40,
        "BS_ADMIN_PASSWORD": "b" * 24,
        "BS_SESSION_SECRET": "c" * 48,
        "BS_AUDIT_CHAIN_SECRET": "d" * 48,
        "BS_DISABLE_DOCS": "1",
        "BS_COOKIE_SECURE": "1",
        "BS_AUDIT_ENABLED": "1",
        "BS_CASES_ROOT": str(tmp_path / "cases"),
        "BS_CASE_HISTORY_PATH": str(tmp_path / "case_history.json"),
        "BS_AUDIT_LOG_PATH": str(tmp_path / "audit.jsonl"),
        "BS_BACKUP_ROOT": str(tmp_path / "backups"),
        "BS_SESSION_TTL_SECONDS": "3600",
    }


def test_init_env_generates_non_placeholder_secrets(tmp_path):
    template = tmp_path / ".env.example"
    template.write_text(
        "BS_API_KEY=change-me\nBS_ADMIN_PASSWORD=change-me\nBS_SESSION_SECRET=change-me\nBS_AUDIT_CHAIN_SECRET=change-me\nBS_DISABLE_DOCS=0\nBS_COOKIE_SECURE=0\n",
        encoding="utf-8",
    )
    body, summary = generate_env_text(template, production=True, https=True)
    assert "BS_DISABLE_DOCS=1" in body
    assert "BS_COOKIE_SECURE=1" in body
    assert "BS_DEPLOYMENT_MODE=production" in body
    assert "change-me" not in body
    assert "BS_SESSION_SECRET" in summary["generated_keys"]


def test_write_env_refuses_overwrite_without_force(tmp_path):
    template = tmp_path / ".env.example"
    template.write_text("BS_API_KEY=change-me\n", encoding="utf-8")
    output = tmp_path / ".env"
    output.write_text("existing=1\n", encoding="utf-8")
    try:
        write_env_file(output, template)
    except FileExistsError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected FileExistsError")
    result = write_env_file(output, template, production=True, force=True)
    assert result["output"] == str(output)
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600


def test_go_live_check_passes_with_production_env(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    result = run_go_live_check(".", env=env, deployment_mode="production")
    assert result["status"] == "pass"
    assert result["score"] >= 90
    names = {check["name"] for check in result["checks"]}
    assert "runtime_authentication" in names
    assert "quality_gate" in names
    assert "project_readiness" in names
    markdown = render_markdown(result)
    assert "Go-Live Readiness" in markdown


def test_go_live_runtime_image_skips_repository_only_checks(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    env["BS_RUNTIME_IMAGE"] = "1"
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(tmp_path, env=env, deployment_mode="production")

    assert result["status"] == "pass"
    assert result["score"] == 100
    names = {check["name"] for check in result["checks"]}
    assert "quality_gate" not in names
    assert "project_readiness" not in names
    assert result["repository_checks"]["status"] == "not_applicable"
    assert "source checkout" in result["next_steps"][0].lower()


def test_go_live_check_fails_placeholder_env(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    env["BS_API_KEY"] = "change-me-long-random-value"
    env["BS_SESSION_SECRET"] = "change-me-long-random-session-secret"
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    result = run_go_live_check(".", env=env, deployment_mode="production")
    assert result["status"] == "fail"
    assert result["summary"]["failed"] >= 1
    assert any(check["name"] == "placeholder_secrets" and check["status"] == "fail" for check in result["checks"])


def test_repository_gate_api_endpoints_are_not_applicable_in_runtime_image(monkeypatch):
    monkeypatch.setenv("BS_RUNTIME_IMAGE", "1")

    for path in ("/api/ops/project-check", "/api/ops/quality-gate"):
        response = client.get(path)
        assert response.status_code == 200
        payload = response.json()
        assert payload["success"] is True
        assert payload["status"] == "not_applicable"
        assert payload["score"] is None
        assert payload["runtime_image"] is True
        assert payload["checks"] == []


def test_go_live_api_endpoint(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    response = client.get("/api/ops/go-live?deployment_mode=production", headers={"X-API-Key": env["BS_API_KEY"]})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "pass"
    assert payload["deployment_mode"] == "production"


def test_go_live_accepts_role_only_browser_auth(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    env.pop("BS_API_KEY")
    env.pop("BS_ADMIN_PASSWORD")
    env["BS_AUTHOR_PASSWORD"] = "author-role-password-123456"
    env["BS_REVIEWER_PASSWORD"] = "reviewer-role-password-123456"
    env["BS_OPERATOR_PASSWORD"] = "operator-role-password-123456"
    for key in ("BS_API_KEY", "BS_ADMIN_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(".", env=env, deployment_mode="production")
    auth = next(
        check for check in result["checks"]
        if check["name"] == "runtime_authentication"
    )
    assert auth["status"] == "pass"
    assert auth["details"]["api_key_enabled"] is False
    assert auth["details"]["password_login_enabled"] is True
    assert auth["details"]["rbac_roles"] == ["author", "operator", "reviewer"]
    assert result["status"] == "pass"


def test_go_live_rejects_invalid_artifact_encryption_key(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    env["BS_ARTIFACT_ENCRYPTION_KEY"] = "invalid-key"
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(".", env=env, deployment_mode="production")
    check = next(
        row for row in result["checks"]
        if row["name"] == "artifact_encryption"
    )
    assert check["status"] == "fail"
    assert result["status"] == "fail"


def test_go_live_accepts_valid_artifact_encryption_key(tmp_path, monkeypatch):
    import base64

    env = _good_env(tmp_path)
    env["BS_ARTIFACT_ENCRYPTION_KEY"] = (
        base64.urlsafe_b64encode(bytes(range(32)))
        .decode("ascii")
        .rstrip("=")
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(".", env=env, deployment_mode="production")
    check = next(
        row for row in result["checks"]
        if row["name"] == "artifact_encryption"
    )
    assert check["status"] == "pass"
    assert check["details"]["enabled"] is True


def test_go_live_rejects_object_storage_without_bucket(tmp_path, monkeypatch):
    import base64

    env = _good_env(tmp_path)
    env["BS_ARTIFACT_ENCRYPTION_KEY"] = (
        base64.urlsafe_b64encode(bytes(range(32)))
        .decode("ascii")
        .rstrip("=")
    )
    env["BS_OBJECT_STORAGE_PROVIDER"] = "s3"
    env["BS_OBJECT_STORAGE_BUCKET"] = ""
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(".", env=env, deployment_mode="production")
    check = next(
        row for row in result["checks"]
        if row["name"] == "object_storage"
    )
    assert check["status"] == "fail"
    assert result["status"] == "fail"


def test_go_live_accepts_s3_object_storage_with_client_encryption(
    tmp_path,
    monkeypatch,
):
    import base64

    env = _good_env(tmp_path)
    env["BS_ARTIFACT_ENCRYPTION_KEY"] = (
        base64.urlsafe_b64encode(bytes(range(32)))
        .decode("ascii")
        .rstrip("=")
    )
    env["BS_OBJECT_STORAGE_PROVIDER"] = "s3"
    env["BS_OBJECT_STORAGE_BUCKET"] = "breachscope-prod"
    env["BS_OBJECT_STORAGE_PREFIX"] = "prod/cases"
    env["BS_OBJECT_STORAGE_REGION"] = "ap-northeast-2"
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(".", env=env, deployment_mode="production")
    check = next(
        row for row in result["checks"]
        if row["name"] == "object_storage"
    )
    assert check["status"] == "pass"
    assert check["details"]["provider"] == "s3"
    assert check["details"]["bucket_configured"] is True
    assert result["status"] == "pass"


def test_go_live_accepts_oidc_only_browser_auth(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    env.pop("BS_API_KEY")
    env.pop("BS_ADMIN_PASSWORD")
    env.update({
        "BS_OIDC_ISSUER_URL": "https://idp.example.test",
        "BS_OIDC_CLIENT_ID": "breachscope",
        "BS_OIDC_REDIRECT_URI": "https://breachscope.example.test/api/auth/oidc/callback",
        "BS_OIDC_OPERATOR_VALUES": "breachscope-operators",
    })
    for key in (
        "BS_API_KEY",
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(".", env=env, deployment_mode="production")
    auth_check = next(
        row for row in result["checks"]
        if row["name"] == "runtime_authentication"
    )
    assert auth_check["status"] == "pass"
    assert auth_check["details"]["password_login_enabled"] is False
    assert auth_check["details"]["oidc_login_enabled"] is True
    assert auth_check["details"]["oidc_roles"] == ["operator"]
    assert result["status"] == "pass"


def test_go_live_rejects_partial_oidc_configuration(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    env.pop("BS_API_KEY")
    env.pop("BS_ADMIN_PASSWORD")
    env.update({
        "BS_OIDC_ISSUER_URL": "https://idp.example.test",
        "BS_OIDC_CLIENT_ID": "breachscope",
        "BS_OIDC_OPERATOR_VALUES": "breachscope-operators",
    })
    for key in (
        "BS_API_KEY",
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
        "BS_OIDC_REDIRECT_URI",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(".", env=env, deployment_mode="production")
    auth_check = next(
        row for row in result["checks"]
        if row["name"] == "runtime_authentication"
    )
    assert auth_check["status"] == "fail"
    assert auth_check["details"]["oidc_login_enabled"] is False
    assert result["status"] == "fail"


def test_go_live_accepts_organization_api_keys_only(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env.pop("BS_API_KEY")
    env.pop("BS_ADMIN_PASSWORD")
    env["BS_ORGANIZATION_API_KEYS"] = json.dumps(
        {
            "org-a": "a" * 32,
            "org-b": "b" * 32,
        }
    )
    for key in ("BS_API_KEY", "BS_ADMIN_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    auth = next(
        row for row in result["checks"]
        if row["name"] == "runtime_authentication"
    )
    assert auth["status"] == "pass"
    assert auth["details"]["api_key_enabled"] is True
    assert auth["details"]["global_api_key_enabled"] is False
    assert auth["details"]["organization_api_key_count"] == 2
    assert auth["details"]["organization_api_key_config_valid"] is True
    assert result["status"] == "pass"


def test_go_live_rejects_invalid_organization_api_keys(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env.pop("BS_API_KEY")
    env.pop("BS_ADMIN_PASSWORD")
    env["BS_ORGANIZATION_API_KEYS"] = "{bad-json"
    for key in ("BS_API_KEY", "BS_ADMIN_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    auth = next(
        row for row in result["checks"]
        if row["name"] == "runtime_authentication"
    )
    assert auth["status"] == "fail"
    assert auth["details"]["organization_api_key_config_valid"] is False
    assert result["status"] == "fail"


def test_go_live_warns_for_weak_organization_api_key(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env.pop("BS_API_KEY")
    env.pop("BS_ADMIN_PASSWORD")
    env["BS_ORGANIZATION_API_KEYS"] = json.dumps(
        {"org-a": "short-key"}
    )
    for key in ("BS_API_KEY", "BS_ADMIN_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    auth = next(
        row for row in result["checks"]
        if row["name"] == "runtime_authentication"
    )
    assert auth["status"] == "warn"
    assert "24+ random" in auth["message"]


def test_go_live_validates_organization_rbac_policy(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env["BS_ORGANIZATION_RBAC_POLICIES"] = json.dumps(
        {
            "org-a": {
                "operator": [
                    "analysis.custom_rules",
                    "rule.operate",
                ],
            }
        }
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    policy = next(
        row for row in result["checks"]
        if row["name"] == "organization_rbac_policy"
    )
    assert policy["status"] == "pass"
    assert policy["details"]["organization_count"] == 1
    assert policy["details"]["role_override_count"] == 1


def test_go_live_rejects_invalid_organization_rbac_policy(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env["BS_ORGANIZATION_RBAC_POLICIES"] = json.dumps(
        {
            "org-a": {
                "operator": ["unknown.permission"],
            }
        }
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    policy = next(
        row for row in result["checks"]
        if row["name"] == "organization_rbac_policy"
    )
    assert policy["status"] == "fail"
    assert result["status"] == "fail"
    assert any(
        "BS_ORGANIZATION_RBAC_POLICIES" in step
        for step in result["next_steps"]
    )


def test_go_live_accepts_oidc_scim_without_claim_role_mapping(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env.pop("BS_ADMIN_PASSWORD")
    env["BS_OIDC_ISSUER_URL"] = "https://idp.example.test"
    env["BS_OIDC_CLIENT_ID"] = "breachscope"
    env["BS_OIDC_REDIRECT_URI"] = (
        "https://breachscope.example.test/api/auth/oidc/callback"
    )
    env["BS_SCIM_BEARER_TOKEN"] = "s" * 40
    env["BS_SCIM_USER_STORE_PATH"] = str(
        tmp_path / "scim_users.json"
    )
    env["BS_SCIM_GROUP_STORE_PATH"] = str(
        tmp_path / "scim_groups.json"
    )
    for name in (
        "BS_OIDC_ADMIN_VALUES",
        "BS_OIDC_AUTHOR_VALUES",
        "BS_OIDC_REVIEWER_VALUES",
        "BS_OIDC_OPERATOR_VALUES",
        "BS_OIDC_DEFAULT_ROLE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    ScimUserDirectory(
        path=Path(env["BS_SCIM_USER_STORE_PATH"])
    ).create_user(
        {
            "userName": "alice@example.test",
            "externalId": "subject-123",
            "active": True,
            BREACHSCOPE_USER_SCHEMA: {
                "role": "operator",
                "organizationId": "org-a",
            },
        }
    )

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    checks = {row["name"]: row for row in result["checks"]}
    assert checks["runtime_authentication"]["status"] == "pass"
    assert checks["runtime_authentication"]["details"][
        "oidc_login_enabled"
    ] is True
    assert checks["runtime_authentication"]["details"][
        "oidc_roles"
    ] == ["operator"]
    assert checks["scim_provisioning"]["status"] == "pass"
    assert checks["scim_provisioning"]["details"][
        "active_users"
    ] == 1
    assert checks["scim_provisioning"]["details"][
        "total_groups"
    ] == 0
    assert checks["scim_provisioning"]["details"][
        "authorized_users"
    ] == 1


def test_go_live_scim_warns_for_zero_active_users_and_rejects_secret_reuse(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env["BS_OIDC_ISSUER_URL"] = "https://idp.example.test"
    env["BS_OIDC_CLIENT_ID"] = "breachscope"
    env["BS_OIDC_REDIRECT_URI"] = (
        "https://breachscope.example.test/api/auth/oidc/callback"
    )
    env["BS_SCIM_BEARER_TOKEN"] = "s" * 40
    env["BS_SCIM_USER_STORE_PATH"] = str(
        tmp_path / "scim_users.json"
    )
    env["BS_SCIM_GROUP_STORE_PATH"] = str(
        tmp_path / "scim_groups.json"
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    check = next(
        row for row in result["checks"]
        if row["name"] == "scim_provisioning"
    )
    assert check["status"] == "warn"
    assert "no active SCIM users" in check["message"]

    env["BS_SCIM_BEARER_TOKEN"] = env["BS_API_KEY"]
    monkeypatch.setenv(
        "BS_SCIM_BEARER_TOKEN",
        env["BS_SCIM_BEARER_TOKEN"],
    )
    reused = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    check = next(
        row for row in reused["checks"]
        if row["name"] == "scim_provisioning"
    )
    assert check["status"] == "fail"
    assert "must not reuse" in check["message"]


def test_go_live_scim_warns_when_active_users_have_no_effective_assignment(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env.pop("BS_ADMIN_PASSWORD")
    env["BS_OIDC_ISSUER_URL"] = "https://idp.example.test"
    env["BS_OIDC_CLIENT_ID"] = "breachscope"
    env["BS_OIDC_REDIRECT_URI"] = (
        "https://breachscope.example.test/api/auth/oidc/callback"
    )
    env["BS_SCIM_BEARER_TOKEN"] = "s" * 40
    env["BS_SCIM_USER_STORE_PATH"] = str(
        tmp_path / "scim_users.json"
    )
    env["BS_SCIM_GROUP_STORE_PATH"] = str(
        tmp_path / "scim_groups.json"
    )
    for name in (
        "BS_OIDC_ADMIN_VALUES",
        "BS_OIDC_AUTHOR_VALUES",
        "BS_OIDC_REVIEWER_VALUES",
        "BS_OIDC_OPERATOR_VALUES",
        "BS_OIDC_DEFAULT_ROLE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    ScimUserDirectory(
        path=Path(env["BS_SCIM_USER_STORE_PATH"]),
        group_path=Path(env["BS_SCIM_GROUP_STORE_PATH"]),
    ).create_user(
        {
            "userName": "staged@example.test",
            "externalId": "subject-staged",
            "active": True,
        }
    )

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    checks = {row["name"]: row for row in result["checks"]}
    scim = checks["scim_provisioning"]
    assert scim["status"] == "warn"
    assert scim["details"]["active_users"] == 1
    assert scim["details"]["authorized_users"] == 0
    assert "no active SCIM user resolves" in scim["message"]


def test_go_live_accepts_group_only_scim_assignment_from_env_paths(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env.pop("BS_ADMIN_PASSWORD")
    env["BS_OIDC_ISSUER_URL"] = "https://idp.example.test"
    env["BS_OIDC_CLIENT_ID"] = "breachscope"
    env["BS_OIDC_REDIRECT_URI"] = (
        "https://breachscope.example.test/api/auth/oidc/callback"
    )
    env["BS_SCIM_BEARER_TOKEN"] = "s" * 40
    env["BS_SCIM_USER_STORE_PATH"] = str(
        tmp_path / "scim_users.json"
    )
    env["BS_SCIM_GROUP_STORE_PATH"] = str(
        tmp_path / "scim_groups.json"
    )
    for name in (
        "BS_OIDC_ADMIN_VALUES",
        "BS_OIDC_AUTHOR_VALUES",
        "BS_OIDC_REVIEWER_VALUES",
        "BS_OIDC_OPERATOR_VALUES",
        "BS_OIDC_DEFAULT_ROLE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    user_directory = ScimUserDirectory(
        path=Path(env["BS_SCIM_USER_STORE_PATH"]),
        group_path=Path(env["BS_SCIM_GROUP_STORE_PATH"]),
    )
    user = user_directory.create_user(
        {
            "userName": "group-only@example.test",
            "externalId": "subject-group-only",
            "active": True,
        }
    )
    ScimGroupDirectory(
        path=Path(env["BS_SCIM_GROUP_STORE_PATH"]),
        user_directory=user_directory,
    ).create_group(
        {
            "displayName": "Group Operators",
            "members": [{"value": user["id"]}],
            BREACHSCOPE_GROUP_SCHEMA: {
                "role": "operator",
                "organizationId": "org-group",
            },
        }
    )

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    checks = {row["name"]: row for row in result["checks"]}
    assert checks["runtime_authentication"]["status"] == "pass"
    assert checks["runtime_authentication"]["details"][
        "oidc_roles"
    ] == ["operator"]
    assert checks["scim_provisioning"]["status"] == "pass"
    assert checks["scim_provisioning"]["details"][
        "authorized_users"
    ] == 1
    assert checks["scim_provisioning"]["details"][
        "total_groups"
    ] == 1



def test_go_live_accepts_sqlite_scim_identity_store(
    tmp_path,
    monkeypatch,
):
    env = _good_env(tmp_path)
    env["BS_OIDC_ISSUER_URL"] = "https://idp.example.test"
    env["BS_OIDC_CLIENT_ID"] = "breachscope"
    env["BS_OIDC_REDIRECT_URI"] = (
        "https://breachscope.example.test/api/auth/oidc/callback"
    )
    env["BS_SCIM_BEARER_TOKEN"] = "s" * 40
    env["BS_SCIM_STORAGE_BACKEND"] = "sqlite"
    env["BS_SCIM_DATABASE_PATH"] = str(
        tmp_path / "scim_identity.db"
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    ScimUserDirectory(
        backend="sqlite",
        database_path=Path(env["BS_SCIM_DATABASE_PATH"]),
        env=env,
    ).create_user(
        {
            "userName": "sqlite-go-live@example.test",
            "externalId": "sqlite-go-live-subject",
            "active": True,
            BREACHSCOPE_USER_SCHEMA: {
                "role": "operator",
                "organizationId": "sqlite-org",
            },
        }
    )

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    checks = {row["name"]: row for row in result["checks"]}
    scim = checks["scim_provisioning"]
    assert scim["status"] == "pass"
    assert scim["details"]["storage_backend"] == "sqlite"
    assert scim["details"]["database_path"] == env[
        "BS_SCIM_DATABASE_PATH"
    ]
    assert scim["details"]["active_users"] == 1
    assert scim["details"]["authorized_users"] == 1


def test_go_live_rejects_invalid_scim_storage_backend(
    tmp_path,
):
    env = _good_env(tmp_path)
    env["BS_SCIM_BEARER_TOKEN"] = "s" * 40
    env["BS_SCIM_STORAGE_BACKEND"] = "postgres"

    result = run_go_live_check(
        ".",
        env=env,
        deployment_mode="production",
    )
    check = next(
        row for row in result["checks"]
        if row["name"] == "scim_provisioning"
    )
    assert check["status"] == "fail"
    assert "storage backend" in check["message"]
    assert "json or sqlite" in check["details"]["error"]
