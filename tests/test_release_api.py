from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_release_info_endpoint_exposes_build_metadata(monkeypatch):
    monkeypatch.setenv("BS_BUILD_VERSION", "v16-test")
    monkeypatch.setenv("BS_BUILD_SHA", "deadbeef")
    response = client.get("/api/ops/release-info")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["release"]["name"] == "breachscope"
    assert payload["release"]["version"] == "v16-test"
    assert payload["release"]["git_sha"] == "deadbeef"
    assert "python_version" in payload["release"]


def test_api_info_includes_release_info(monkeypatch):
    monkeypatch.setenv("BS_BUILD_VERSION", "v16-info")
    response = client.get("/api/info")
    assert response.status_code == 200
    payload = response.json()
    assert payload["release_info_endpoint"] == "/api/ops/release-info"
    assert payload["release"]["version"] == "v16-info"
