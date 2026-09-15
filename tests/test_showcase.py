from pathlib import Path
from zipfile import ZipFile

from fastapi.testclient import TestClient

from api.main import app
from breachscope.showcase import _index_html, _social_preview_svg, build_showcase

client = TestClient(app)


def test_build_showcase_creates_static_landing_bundle(tmp_path):
    out = tmp_path / "showcase"
    result = build_showcase(".", out, clean=True, render_pdf=False)

    assert result["success"] is True
    assert result["demo_summary"]["findings"] >= 50
    assert result["demo_summary"]["rule_count"] >= 50
    assert result["project_readiness"]["score"] >= 90
    assert result["quality_gate"]["score"] >= 90

    required = [
        "index.html",
        "README.md",
        "assets/showcase.css",
        "assets/social-preview.svg",
        "data/showcase_summary.json",
        "reports/breachscope_showcase_report.html",
        "reports/breachscope_showcase_report.json",
        "reports/breachscope_showcase_report.csv",
        "reports/breachscope_showcase_report.iocs.csv",
        "reports/breachscope_showcase_report.rules.csv",
        "reports/breachscope_showcase_report.manifest.json",
        "reports/breachscope_showcase_report.zip",
        "showcase_manifest.json",
        "showcase_result.json",
        "SHA256SUMS.txt",
        "breachscope-showcase.zip",
    ]
    for rel in required:
        assert (out / rel).exists(), rel

    html = (out / "index.html").read_text(encoding="utf-8")
    assert "BreachScope" in html
    assert "reports/breachscope_showcase_report.html" in html
    assert "assets/social-preview.svg" in html

    with ZipFile(out / "breachscope-showcase.zip") as zf:
        names = set(zf.namelist())
    assert "breachscope-showcase/index.html" in names
    assert "breachscope-showcase/assets/social-preview.svg" in names
    assert "breachscope-showcase/reports/breachscope_showcase_report.html" in names


def test_showcase_preview_api():
    response = client.get("/api/ops/showcase-preview")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["showcase"]["scenario_count"] >= 10
    assert payload["showcase"]["rule_count"] >= 50
    assert payload["showcase"]["entrypoint"] == "index.html"
    assert "python scripts/build_showcase.py" in payload["showcase"]["recommended_command"]

def test_showcase_copy_uses_dynamic_counts():
    demo = {
        "risk_score": 1,
        "risk_level": "low",
        "findings": 2,
        "events": 3,
        "rule_count": 123,
        "rule_techniques": 45,
        "rule_coverage": 67.8,
        "scenario_count": 17,
        "top_tactics": [],
    }
    page = _index_html({"generated_at": "now", "version": "9.9.9"}, demo, {"score": 1}, {"score": 1}, [])
    preview = _social_preview_svg({"name": "BreachScope"}, demo)
    assert "<li>123" in page
    assert "What this demo includes" in page
    assert "17 safe demo scenarios" in preview

