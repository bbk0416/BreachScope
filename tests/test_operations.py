import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.services.backup_service import BackupService
from api.services.case_history import CaseHistoryService

client = TestClient(app)


def _report(score=10, level="low"):
    return {
        "summary": {
            "total_findings": 1,
            "risk": {"score": score, "level": level},
            "host_risk_summary": [{"host": "WS-01", "score": score, "level": level, "findings": 1}],
            "mitre_counts": {"T1059.001": 1},
        }
    }


def _create_case(svc: CaseHistoryService, work_dir: Path, score=10):
    (work_dir / "out").mkdir(parents=True, exist_ok=True)
    (work_dir / "out" / "report.html").write_text("<html>ok</html>", encoding="utf-8")
    (work_dir / "out" / "report.json").write_text(json.dumps(_report(score=score)), encoding="utf-8")
    return svc.register_case(work_dir, _report(score=score))


def test_case_prune_dry_run_and_apply(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))

    svc = CaseHistoryService()
    old_case = _create_case(svc, tmp_path / "cases" / "old", score=20)
    new_case = _create_case(svc, tmp_path / "cases" / "new", score=80)

    data = svc._read_index()
    old_stamp = (datetime.now(timezone.utc) - timedelta(days=45)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for row in data["cases"]:
        if row["case_id"] == old_case.case_id:
            row["created_at"] = old_stamp
            row["updated_at"] = old_stamp
    svc._write_index(data)

    dry = client.post("/api/cases/prune", params={"keep_last": 1, "older_than_days": 30, "dry_run": "true"})
    assert dry.status_code == 200
    assert dry.json()["candidate_count"] == 1
    assert (tmp_path / "cases" / "old").exists()

    applied = client.post("/api/cases/prune", params={"keep_last": 1, "older_than_days": 30, "dry_run": "false"})
    assert applied.status_code == 200
    assert applied.json()["removed_case_records"] == 1
    assert not (tmp_path / "cases" / "old").exists()
    assert svc.get_case(new_case.case_id)["case_id"] == new_case.case_id


def test_backup_service_and_api_download(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(tmp_path / "backups"))

    svc = CaseHistoryService()
    _create_case(svc, tmp_path / "cases" / "case_a", score=33)
    (tmp_path / "audit.jsonl").write_text('{"action":"unit"}\n', encoding="utf-8")

    backup = BackupService().create_backup(label="unit")
    assert backup["backup_id"]
    assert backup["file_count"] >= 3

    listed = client.get("/api/backups")
    assert listed.status_code == 200
    assert listed.json()["backups"][0]["backup_id"] == backup["backup_id"]

    integrity = client.get(f"/api/backups/{backup['backup_id']}/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["integrity"]["sha256"] == backup["sha256"]

    download = client.get(f"/api/backups/{backup['backup_id']}/download")
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/zip"

    deleted = client.delete(f"/api/backups/{backup['backup_id']}")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
