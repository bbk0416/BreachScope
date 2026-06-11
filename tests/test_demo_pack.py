from pathlib import Path
from zipfile import ZipFile

from fastapi.testclient import TestClient

from api.main import app
from breachscope.demo_pack import build_demo_pack

client = TestClient(app)


def test_build_demo_pack_creates_shareable_bundle(tmp_path):
    out = tmp_path / "demo_pack"
    result = build_demo_pack(".", out, clean=True, render_pdf=False)

    assert result["success"] is True
    assert result["demo_summary"]["total_findings"] >= 50
    assert result["project_readiness"]["score"] >= 90
    assert result["quality_gate"]["score"] >= 90

    required = [
        "README.md",
        "02_DEMO_WALKTHROUGH.md",
        "03_PORTFOLIO_PITCH.md",
        "04_RELEASE_NOTES.md",
        "05_GITHUB_UPLOAD_CHECKLIST.md",
        "06_SCREENSHOT_GUIDE.md",
        "demo_pack_manifest.json",
        "demo_pack_result.json",
        "SHA256SUMS.txt",
        "reports/breachscope_demo_report.html",
        "reports/breachscope_demo_report.json",
        "reports/breachscope_demo_report.csv",
        "reports/breachscope_demo_report.iocs.csv",
        "reports/breachscope_demo_report.rules.csv",
        "reports/breachscope_demo_report.manifest.json",
        "reports/breachscope_demo_report.zip",
        "breachscope-demo-pack.zip",
    ]
    for rel in required:
        assert (out / rel).exists(), rel

    with ZipFile(out / "breachscope-demo-pack.zip") as zf:
        names = set(zf.namelist())
    assert "breachscope-demo-pack/README.md" in names
    assert "breachscope-demo-pack/reports/breachscope_demo_report.html" in names
    assert "breachscope-demo-pack/demo_pack_manifest.json" in names


def test_demo_pack_preview_api():
    response = client.get("/api/ops/demo-pack-preview")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["demo_pack"]["scenario_count"] >= 10
    assert payload["demo_pack"]["rule_count"] >= 50
    assert "python scripts/build_demo_pack.py" in payload["demo_pack"]["recommended_command"]
