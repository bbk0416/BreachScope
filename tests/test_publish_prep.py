from pathlib import Path
from zipfile import ZipFile

from fastapi.testclient import TestClient

from api.main import app
from breachscope.publish import build_publish_prep, inspect_zip_hygiene

client = TestClient(app)


def test_build_publish_prep_creates_final_launch_package(tmp_path):
    out = tmp_path / "publish"
    result = build_publish_prep(".", out, clean=True, render_pdf=False)

    assert result["success"] is True
    assert result["project_readiness"]["score"] >= 95
    assert result["quality_gate"]["score"] >= 95
    assert result["go_live"]["score"] >= 95
    assert result["zip_hygiene_status"] == "pass"

    required = [
        "PUBLIC_LAUNCH_SUMMARY.md",
        "GITHUB_PUBLISH_COMMANDS.md",
        "RELEASE_NOTE_DRAFT.md",
        "publish_manifest.json",
        "SHA256SUMS.txt",
        "dist/breachscope-1.0.0-source.zip",
        "dist/SHA256SUMS.txt",
        "dist/release_manifest.json",
        "demo_pack/breachscope-demo-pack.zip",
        "showcase/breachscope-showcase.zip",
        "breachscope-public-launch-pack.zip",
    ]
    for rel in required:
        assert (out / rel).exists(), rel

    with ZipFile(out / "breachscope-public-launch-pack.zip") as zf:
        names = set(zf.namelist())
    assert "breachscope-public-launch-pack/PUBLIC_LAUNCH_SUMMARY.md" in names
    assert "breachscope-public-launch-pack/GITHUB_PUBLISH_COMMANDS.md" in names
    assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)


def test_inspect_zip_hygiene_detects_cache_files(tmp_path):
    bad_zip = tmp_path / "bad.zip"
    with ZipFile(bad_zip, "w") as zf:
        zf.writestr("project/api/__pycache__/main.cpython-311.pyc", b"bad")
        zf.writestr("project/.env", "BS_API_KEY=secret")
    result = inspect_zip_hygiene(bad_zip)
    assert result["status"] == "fail"
    assert len(result["issues"]) == 2


def test_publish_prep_preview_api():
    response = client.get("/api/ops/publish-prep-preview")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["publish_prep"]["scenario_count"] >= 10
    assert payload["publish_prep"]["rule_count"] >= 50
    assert "publish_prep.py" in payload["publish_prep"]["recommended_command"]
