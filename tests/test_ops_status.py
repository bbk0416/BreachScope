import json
from fastapi.testclient import TestClient

from api.main import app
from api.services.ops_status import _security_checks, prometheus_metrics

client = TestClient(app)


def test_liveness_and_readiness_endpoints():
    live = client.get("/api/health/live")
    assert live.status_code == 200
    assert live.json()["status"] == "live"
    assert "uptime_seconds" in live.json()

    ready = client.get("/api/health/ready")
    assert ready.status_code == 200
    data = ready.json()
    assert data["status"] in {"ready", "not_ready"}
    assert any(check["name"] == "rulepack" for check in data["checks"])


def test_metrics_json_and_prometheus_format():
    metrics_json = client.get("/api/metrics.json")
    assert metrics_json.status_code == 200
    data = metrics_json.json()["metrics"]
    assert data["rulepack"]["total_rules"] >= 50
    assert "cases_total" in data

    metrics = client.get("/api/metrics")
    assert metrics.status_code == 200
    assert "breachscope_cases_total" in metrics.text
    assert "text/plain" in metrics.headers["content-type"]
    assert "breachscope_rulepack_rules_total" in prometheus_metrics(data)


def test_config_check_and_self_test(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(tmp_path / "backups"))

    config = client.get("/api/ops/config-check")
    assert config.status_code == 200
    payload = config.json()
    assert payload["status"] in {"pass", "warn", "fail"}
    assert any(check["name"] == "rulepack" for check in payload["checks"])

    self_test = client.post("/api/ops/self-test")
    assert self_test.status_code == 200
    result = self_test.json()
    assert result["success"] is True
    assert result["findings"] > 0
    assert result["artifacts"]["zip"] is True


def test_readiness_fails_for_object_storage_without_artifact_encryption(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(tmp_path / "backups"))
    monkeypatch.setenv("BS_OBJECT_STORAGE_PROVIDER", "s3")
    monkeypatch.setenv("BS_OBJECT_STORAGE_BUCKET", "breachscope-test")
    monkeypatch.delenv("BS_ARTIFACT_ENCRYPTION_KEY", raising=False)

    response = client.get("/api/health/ready")
    assert response.status_code == 503
    checks = {row["name"]: row for row in response.json()["checks"]}
    assert checks["object_storage"]["status"] == "fail"


def test_config_check_accepts_static_s3_configuration(
    tmp_path,
    monkeypatch,
):
    import base64

    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(tmp_path / "backups"))
    monkeypatch.setenv("BS_OBJECT_STORAGE_PROVIDER", "s3")
    monkeypatch.setenv("BS_OBJECT_STORAGE_BUCKET", "breachscope-test")
    monkeypatch.setenv(
        "BS_ARTIFACT_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("="),
    )

    response = client.get("/api/ops/config-check")
    assert response.status_code == 200
    checks = {row["name"]: row for row in response.json()["checks"]}
    assert checks["object_storage"]["status"] == "pass"
    assert checks["object_storage"]["details"]["provider"] == "s3"


def test_security_checks_validate_organization_api_keys(monkeypatch):
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv(
        "BS_ORGANIZATION_API_KEYS",
        json.dumps({"org-a": "a" * 32}),
    )
    checks = {row.name: row for row in _security_checks()}
    assert checks["auth_enabled"].status == "pass"
    assert checks["organization_api_keys"].status == "pass"
    assert checks["organization_api_keys"].details["count"] == 1

    monkeypatch.setenv("BS_ORGANIZATION_API_KEYS", "{bad-json")
    checks = {row.name: row for row in _security_checks()}
    assert checks["organization_api_keys"].status == "fail"


def test_security_checks_reject_session_secret_reused_as_org_key(
    monkeypatch,
):
    secret = "s" * 40
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv(
        "BS_ORGANIZATION_API_KEYS",
        json.dumps({"org-a": secret}),
    )
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password-12345")
    monkeypatch.setenv("BS_SESSION_SECRET", secret)

    checks = {row.name: row for row in _security_checks()}
    assert checks["session_secret"].status == "warn"
    assert "should not equal" in checks["session_secret"].message


def test_security_checks_validate_organization_rbac_policy(monkeypatch):
    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        json.dumps(
            {
                "org-a": {
                    "operator": ["analysis.custom_rules"],
                    "author": [],
                }
            }
        ),
    )
    checks = {row.name: row for row in _security_checks()}
    assert checks["organization_rbac_policy"].status == "pass"
    assert (
        checks["organization_rbac_policy"].details[
            "organization_count"
        ]
        == 1
    )
    assert (
        checks["organization_rbac_policy"].details[
            "role_override_count"
        ]
        == 2
    )

    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        '{"org-a":{"operator":["not.real"]}}',
    )
    checks = {row.name: row for row in _security_checks()}
    assert checks["organization_rbac_policy"].status == "fail"
