import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.services.audit_log import AuditLogService

client = TestClient(app)


def test_audit_service_sanitizes_and_exports(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")

    svc = AuditLogService()
    entry = svc.record(
        "unit.test",
        actor="tester",
        auth_method="unit",
        details={"password": "secret", "message": "ok"},
    )

    assert entry is not None
    events = svc.read_events(limit=10)
    assert events[0]["action"] == "unit.test"
    assert events[0]["details"]["password"] == "<redacted>"
    assert "unit.test" in svc.export_jsonl(events)
    csv_data = svc.export_csv(events)
    assert "timestamp,event_id,action" in csv_data
    integrity = svc.verify_chain()
    assert integrity["exists"] is True
    assert integrity["events"] == 1
    assert len(integrity["sha256"]) == 64


def test_audit_api_records_analysis_download_and_delete(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.delenv("BS_ADMIN_PASSWORD", raising=False)

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
    case_id = response.json()["case_id"]

    download = client.get(f"/api/cases/{case_id}/report", params={"file_type": "json"})
    assert download.status_code == 200

    deleted = client.delete(f"/api/cases/{case_id}")
    assert deleted.status_code == 200

    audit = client.get("/api/audit", params={"limit": 10})
    assert audit.status_code == 200
    actions = [e["action"] for e in audit.json()["events"]]
    assert "analysis.run" in actions
    assert "case.download" in actions
    assert "case.delete" in actions

    exported = client.get("/api/audit/export", params={"file_type": "csv"})
    assert exported.status_code == 200
    assert "analysis.run" in exported.text

    integrity = client.get("/api/audit/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["integrity"]["events"] >= 3
