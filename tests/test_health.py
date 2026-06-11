"""
기본 API/웹 헬스 체크 테스트
"""
import json
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_root_serves_web_ui():
    """루트 경로는 웹 UI HTML을 반환한다."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "BreachScope Web UI" in response.text


def test_api_info():
    """API 정보 엔드포인트 테스트"""
    response = client.get("/api/info")
    assert response.status_code == 200
    assert response.json()["name"] == "BreachScope"


def test_health_check():
    """헬스 체크 엔드포인트 테스트"""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_rules_endpoint():
    """규칙 목록 엔드포인트 테스트"""
    response = client.get("/api/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["count"] >= 1
    assert "title" in data["rules"][0]


def test_analyze_preserves_report_for_download(tmp_path: Path):
    """분석 직후 리포트 다운로드가 가능해야 한다."""
    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "WS-01",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\alice",
        "command_line": "powershell.exe -encodedcommand AAAABBBBCCCCDDDD",
    }
    sample = tmp_path / "events.jsonl"
    sample.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")

    with sample.open("rb") as f:
        response = client.post(
            "/api/analyze",
            files=[("files", ("events.jsonl", f, "application/octet-stream"))],
            data={"use_repo_rules": "true", "min_severity": "low", "redact": "true"},
        )
    assert response.status_code == 200
    data = response.json()
    work_dir = data["work_dir"]
    assert Path(work_dir).exists()
    assert data["risk_score"] > 0
    assert data["risk_level"] in {"low", "medium", "high", "critical"}
    assert data["manifest_path"]
    assert data["package_path"]
    assert data["rule_catalog_path"]
    assert data["preview"]["risk"]["score"] > 0
    assert data["preview"]["top_findings"]

    preview_url = "/api/report-preview/" + quote(work_dir, safe="")
    preview = client.get(preview_url)
    assert preview.status_code == 200
    assert preview.json()["risk"]["score"] == data["preview"]["risk"]["score"]

    download_url = "/api/report/" + quote(work_dir, safe="")
    download = client.get(download_url, params={"file_type": "html"})
    assert download.status_code == 200
    assert "text/html" in download.headers["content-type"]

    manifest = client.get(download_url, params={"file_type": "manifest"})
    assert manifest.status_code == 200
    manifest_data = manifest.json()
    assert manifest_data["case"]["total_findings"] >= 1
    assert manifest_data["evidence_hashes"]["events"]

    rule_catalog = client.get(download_url, params={"file_type": "rules"})
    assert rule_catalog.status_code == 200
    assert "id,name,severity" in rule_catalog.text

    package = client.get(download_url, params={"file_type": "zip"})
    assert package.status_code == 200
    package_path = Path(work_dir) / "out" / "downloaded_report.zip"
    package_path.write_bytes(package.content)
    with zipfile.ZipFile(package_path) as zf:
        assert "report.html" in zf.namelist()
        assert "report.manifest.json" in zf.namelist()
        assert "report.rules.csv" in zf.namelist()
