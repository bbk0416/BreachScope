import json
from pathlib import Path

import pytest

from fastapi.testclient import TestClient

from api.main import app
from api.services.case_history import CaseHistoryService


client = TestClient(app)


def _sample_report(total_findings: int = 2):
    return {
        "summary": {
            "total_findings": total_findings,
            "risk": {"score": 73, "level": "high"},
            "host_risk_summary": [{"host": "WS-01", "score": 73, "level": "high", "findings": total_findings}],
            "mitre_counts": {"T1059.001": 1, "T1105": 1},
            "executive_summary": ["테스트 요약"],
        }
    }


def test_case_history_register_list_and_delete(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))

    work_dir = tmp_path / "cases" / "bs_case_unit"
    (work_dir / "out").mkdir(parents=True)
    (work_dir / "out" / "report.html").write_text("<html>ok</html>", encoding="utf-8")
    (work_dir / "out" / "report.json").write_text(json.dumps(_sample_report()), encoding="utf-8")

    svc = CaseHistoryService()
    record = svc.register_case(work_dir, _sample_report())

    rows = svc.list_cases()
    assert rows[0]["case_id"] == record.case_id
    assert rows[0]["risk_score"] == 73
    assert rows[0]["hosts"] == ["WS-01"]
    assert rows[0]["techniques"] == ["T1059.001", "T1105"]
    assert rows[0]["artifacts"]["html"] is True

    result = svc.delete_case(record.case_id)
    assert result["deleted"] is True
    assert result["removed_files"] is True
    assert not work_dir.exists()


def test_cases_api_after_analysis_supports_case_id_download_and_delete(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))

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
    assert data["case_id"]
    assert data["case"]["risk_score"] > 0

    cases = client.get("/api/cases")
    assert cases.status_code == 200
    assert cases.json()["cases"][0]["case_id"] == data["case_id"]

    detail = client.get(f"/api/cases/{data['case_id']}")
    assert detail.status_code == 200
    assert detail.json()["preview"]["risk"]["score"] == data["preview"]["risk"]["score"]

    download = client.get(f"/api/cases/{data['case_id']}/report", params={"file_type": "html"})
    assert download.status_code == 200
    assert "text/html" in download.headers["content-type"]

    deleted = client.delete(f"/api/cases/{data['case_id']}")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert deleted.json()["removed_files"] is True


def test_case_workflow_update_and_summary(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))

    work_dir = tmp_path / "cases" / "workflow_case"
    (work_dir / "out").mkdir(parents=True)
    (work_dir / "out" / "report.html").write_text("<html>ok</html>", encoding="utf-8")
    (work_dir / "out" / "report.json").write_text(json.dumps(_sample_report()), encoding="utf-8")

    record = CaseHistoryService().register_case(work_dir, _sample_report())
    response = client.patch(
        f"/api/cases/{record.case_id}/workflow",
        json={
            "workflow_status": "investigating",
            "assignee": "analyst-a",
            "tags": ["powershell", "priority high", "powershell"],
            "notes": "초동분석 진행 중",
            "severity_override": "critical",
            "title": "WS-01 PowerShell investigation",
        },
    )
    assert response.status_code == 200
    case = response.json()["case"]
    assert case["workflow_status"] == "investigating"
    assert case["assignee"] == "analyst-a"
    assert case["tags"] == ["powershell", "priority-high"]
    assert case["severity_override"] == "critical"
    assert case["updated_by"] == "local-demo"

    detail = client.get(f"/api/cases/{record.case_id}")
    assert detail.status_code == 200
    assert detail.json()["case"]["workflow_status"] == "investigating"

    summary = client.get("/api/cases/workflow/summary")
    assert summary.status_code == 200
    assert summary.json()["summary"]["by_status"]["investigating"] == 1
    assert summary.json()["summary"]["by_assignee"]["analyst-a"] == 1
    assert summary.json()["summary"]["by_severity"]["critical"] == 1

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "case.workflow.update" in audit_text


def test_case_workflow_update_rejects_invalid_status(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))

    work_dir = tmp_path / "cases" / "workflow_bad"
    (work_dir / "out").mkdir(parents=True)
    (work_dir / "out" / "report.html").write_text("<html>ok</html>", encoding="utf-8")
    (work_dir / "out" / "report.json").write_text(json.dumps(_sample_report()), encoding="utf-8")
    record = CaseHistoryService().register_case(work_dir, _sample_report())

    response = client.patch(f"/api/cases/{record.case_id}/workflow", json={"workflow_status": "wat"})
    assert response.status_code == 400



def test_case_history_records_reanalysis_lineage_within_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_root = tmp_path / "cases"
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "history.json"),
    )
    history = CaseHistoryService(organization_id="org-a")

    source_work = cases_root / "source"
    target_work = cases_root / "target"
    for work in (source_work, target_work):
        (work / "out").mkdir(parents=True)
        (work / "out" / "report.json").write_text(
            json.dumps(_sample_report()),
            encoding="utf-8",
        )

    source = history.register_case(
        source_work,
        _sample_report(),
    )
    target = history.register_case(
        target_work,
        _sample_report(),
    )

    manifest_sha256 = "a" * 64
    updated = history.set_analysis_lineage(
        target.case_id,
        source_case_id=source.case_id,
        source="object_storage",
        source_manifest_sha256=manifest_sha256,
        updated_by="operator",
    )

    lineage = updated["analysis_lineage"]
    assert lineage["source_case_id"] == source.case_id
    assert lineage["source"] == "object_storage"
    assert lineage["reanalyzed_by"] == "operator"
    assert lineage["reanalyzed_at"]
    assert lineage["source_manifest_sha256"] == manifest_sha256

    with pytest.raises(
        ValueError,
        match="source_manifest_sha256",
    ):
        history.set_analysis_lineage(
            target.case_id,
            source_case_id=source.case_id,
            source="object_storage",
            source_manifest_sha256="not-a-sha256",
            updated_by="operator",
        )


def test_case_history_reanalysis_lineage_cannot_cross_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_root = tmp_path / "cases"
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "history.json"),
    )
    org_a = CaseHistoryService(organization_id="org-a")
    org_b = CaseHistoryService(organization_id="org-b")

    source_work = cases_root / "source"
    target_work = cases_root / "target"
    for work in (source_work, target_work):
        (work / "out").mkdir(parents=True)
        (work / "out" / "report.json").write_text(
            json.dumps(_sample_report()),
            encoding="utf-8",
        )

    source = org_a.register_case(
        source_work,
        _sample_report(),
    )
    target = org_b.register_case(
        target_work,
        _sample_report(),
    )

    with pytest.raises(KeyError):
        org_b.set_analysis_lineage(
            target.case_id,
            source_case_id=source.case_id,
            source="object_storage",
            updated_by="operator",
        )
