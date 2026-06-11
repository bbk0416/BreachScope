from pathlib import Path
import os

from fastapi.testclient import TestClient

from api.main import app
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


def test_go_live_api_endpoint(tmp_path, monkeypatch):
    env = _good_env(tmp_path)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    response = client.get("/api/ops/go-live?deployment_mode=production", headers={"X-API-Key": env["BS_API_KEY"]})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "pass"
    assert payload["deployment_mode"] == "production"
