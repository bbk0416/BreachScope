from fastapi.testclient import TestClient

from api.main import app
from breachscope.project_readiness import render_markdown, run_project_readiness

client = TestClient(app)


def test_project_readiness_module_passes_core_checks():
    result = run_project_readiness(".")
    assert result["success"] is True
    assert result["score"] >= 90
    names = {check["name"] for check in result["checks"]}
    assert "rulepack_coverage" in names
    assert "demo_scenarios" in names
    assert "github_collaboration_templates" in names
    markdown = render_markdown(result)
    assert "BreachScope Project Readiness Report" in markdown
    assert "rulepack_coverage" in markdown


def test_project_check_api_endpoint():
    response = client.get("/api/ops/project-check")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["score"] >= 90
    assert payload["summary"]["failed"] == 0
