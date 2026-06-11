from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from breachscope.quality_gate import render_markdown, run_quality_gate

client = TestClient(app)


def test_quality_gate_passes_current_repository():
    result = run_quality_gate(".")
    assert result["success"] is True
    assert result["score"] >= 95
    names = {check["name"] for check in result["checks"]}
    assert "secret_scan" in names
    assert "release_hygiene" in names
    assert "markdown_links" in names
    markdown = render_markdown(result)
    assert "BreachScope Quality Gate Report" in markdown
    assert "secret_scan" in markdown


def test_quality_gate_detects_runtime_file_and_secret(tmp_path: Path):
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    (tmp_path / ".env").write_text("BS_API_KEY=" + "A" * 32 + "\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text("report vulnerability\n", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "DEPLOYMENT.md").write_text("BS_API_KEY BS_ADMIN_PASSWORD BS_SESSION_SECRET\n", encoding="utf-8")
    (docs / "CI_CD.md").write_text("GitHub Actions pytest\n", encoding="utf-8")
    (docs / "RELEASE.md").write_text("SHA256 release_manifest\n", encoding="utf-8")

    result = run_quality_gate(tmp_path)
    assert result["success"] is False
    statuses = {check["name"]: check["status"] for check in result["checks"]}
    assert statuses["forbidden_runtime_files"] == "fail"
    assert statuses["secret_scan"] == "fail"


def test_quality_gate_api_endpoint():
    response = client.get("/api/ops/quality-gate")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["score"] >= 95
    assert payload["summary"]["failed"] == 0
