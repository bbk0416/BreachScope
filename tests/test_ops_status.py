from fastapi.testclient import TestClient

from api.main import app
from api.services.ops_status import prometheus_metrics

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
