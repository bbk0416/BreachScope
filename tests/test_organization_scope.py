from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.case_history import CaseHistoryService
from api.services.organization_scope import (
    OrganizationScopeError,
    normalize_organization_id,
)


def _report(score: int = 42) -> dict:
    return {
        "summary": {
            "total_findings": 1,
            "risk": {"score": score, "level": "medium"},
            "host_risk_summary": [
                {"host": "WS-01", "score": score, "level": "medium", "findings": 1}
            ],
            "mitre_counts": {"T1059.001": 1},
        }
    }


def _case(
    service: CaseHistoryService,
    root: Path,
    name: str,
    *,
    score: int = 42,
):
    work = root / name
    (work / "out").mkdir(parents=True, exist_ok=True)
    (work / "out" / "report.html").write_text("<html>ok</html>", encoding="utf-8")
    (work / "out" / "report.json").write_text(
        json.dumps(_report(score)),
        encoding="utf-8",
    )
    return service.register_case(work, _report(score))


def _clear_auth(monkeypatch) -> None:
    for name in (
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
        "BS_OIDC_ISSUER_URL",
        "BS_OIDC_CLIENT_ID",
        "BS_OIDC_CLIENT_SECRET",
        "BS_OIDC_REDIRECT_URI",
        "BS_OIDC_ORGANIZATION_CLAIM",
        "BS_OIDC_DEFAULT_ROLE",
        "BS_OIDC_ADMIN_VALUES",
        "BS_OIDC_AUTHOR_VALUES",
        "BS_OIDC_REVIEWER_VALUES",
        "BS_OIDC_OPERATOR_VALUES",
    ):
        monkeypatch.delenv(name, raising=False)


def test_organization_id_is_fail_closed_and_canonicalized():
    assert normalize_organization_id(" ACME-Blue ") == "acme-blue"
    assert normalize_organization_id("team.one") == "team.one"
    with pytest.raises(OrganizationScopeError):
        normalize_organization_id("../other", default=None)
    with pytest.raises(OrganizationScopeError):
        normalize_organization_id("has space", default=None)


def test_case_history_scopes_legacy_and_new_records(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_DEFAULT_ORGANIZATION_ID", "legacy-org")

    legacy = CaseHistoryService()
    legacy_record = _case(legacy, tmp_path / "cases", "legacy")
    assert legacy_record.organization_id == "legacy-org"

    raw = legacy._read_index()
    for row in raw["cases"]:
        if row["case_id"] == legacy_record.case_id:
            row.pop("organization_id", None)
    legacy._write_index(raw)

    org_a = CaseHistoryService(organization_id="org-a")
    org_b = CaseHistoryService(organization_id="org-b")
    a_record = _case(org_a, tmp_path / "cases", "org-a")
    b_record = _case(org_b, tmp_path / "cases", "org-b")

    assert [row["case_id"] for row in legacy.list_cases()] == [legacy_record.case_id]
    assert [row["case_id"] for row in org_a.list_cases()] == [a_record.case_id]
    assert [row["case_id"] for row in org_b.list_cases()] == [b_record.case_id]
    all_case_ids = {
        row["case_id"] for row in org_a.list_all_cases_for_operations()
    }
    assert all_case_ids == {
        legacy_record.case_id,
        a_record.case_id,
        b_record.case_id,
    }
    assert org_a.get_case(a_record.case_id)["organization_id"] == "org-a"

    with pytest.raises(KeyError):
        org_a.get_case(b_record.case_id)
    with pytest.raises(KeyError):
        org_a.update_case_workflow(b_record.case_id, notes="cross-org")
    with pytest.raises(KeyError):
        org_a.delete_case(b_record.case_id, remove_files=False)


def test_prune_never_removes_other_organization_records(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))

    org_a = CaseHistoryService(organization_id="org-a")
    org_b = CaseHistoryService(organization_id="org-b")
    a_record = _case(org_a, tmp_path / "cases", "org-a")
    b_record = _case(org_b, tmp_path / "cases", "org-b")

    result = org_a.prune_cases(keep_last=0, dry_run=False, remove_files=False)
    assert result["removed_case_records"] == 1
    with pytest.raises(KeyError):
        org_a.get_case(a_record.case_id)
    assert org_b.get_case(b_record.case_id)["case_id"] == b_record.case_id


def test_api_key_case_scope_blocks_cross_organization_access(
    tmp_path: Path,
    monkeypatch,
):
    _clear_auth(monkeypatch)
    monkeypatch.setenv("BS_API_KEY", "organization-test-api-key")
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))

    org_a = CaseHistoryService(organization_id="org-a")
    org_b = CaseHistoryService(organization_id="org-b")
    a_record = _case(org_a, tmp_path / "cases", "org-a")
    b_record = _case(org_b, tmp_path / "cases", "org-b")

    client = TestClient(app)
    headers_a = {
        "x-api-key": "organization-test-api-key",
        "x-breachscope-organization": "org-a",
    }

    listed = client.get("/api/cases", headers=headers_a)
    assert listed.status_code == 200
    assert [row["case_id"] for row in listed.json()["cases"]] == [a_record.case_id]

    assert client.get(
        f"/api/cases/{b_record.case_id}",
        headers=headers_a,
    ).status_code == 404
    assert client.patch(
        f"/api/cases/{b_record.case_id}/workflow",
        headers=headers_a,
        json={"notes": "must not cross scope"},
    ).status_code == 404
    assert client.delete(
        f"/api/cases/{b_record.case_id}",
        headers=headers_a,
        params={"remove_files": "false"},
    ).status_code == 404
    assert client.post(
        f"/api/cases/{b_record.case_id}/object-storage/replicate",
        headers=headers_a,
    ).status_code == 404

    summary = client.get("/api/cases/workflow/summary", headers=headers_a)
    assert summary.status_code == 200
    assert summary.json()["summary"]["total"] == 1

    invalid = client.get(
        "/api/cases",
        headers={
            "x-api-key": "organization-test-api-key",
            "x-breachscope-organization": "../escape",
        },
    )
    assert invalid.status_code == 400

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(row.get("organization_id") == "org-a" for row in events)


def test_analysis_registers_case_in_api_key_organization(
    tmp_path: Path,
    monkeypatch,
):
    _clear_auth(monkeypatch)
    monkeypatch.setenv("BS_API_KEY", "organization-analysis-api-key")
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))

    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "WS-ORG",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\alice",
        "command_line": "powershell.exe -encodedcommand AAAABBBBCCCCDDDD",
    }
    sample = tmp_path / "events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    client = TestClient(app)
    headers_a = {
        "x-api-key": "organization-analysis-api-key",
        "x-breachscope-organization": "org-a",
    }
    with sample.open("rb") as handle:
        response = client.post(
            "/api/analyze",
            headers=headers_a,
            files=[("files", ("events.jsonl", handle, "application/octet-stream"))],
            data={"use_repo_rules": "true", "min_severity": "low", "redact": "true"},
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["case_id"]
    assert body["case"]["organization_id"] == "org-a"

    listed_a = client.get("/api/cases", headers=headers_a)
    assert listed_a.status_code == 200
    assert body["case_id"] in [row["case_id"] for row in listed_a.json()["cases"]]

    listed_b = client.get(
        "/api/cases",
        headers={
            "x-api-key": "organization-analysis-api-key",
            "x-breachscope-organization": "org-b",
        },
    )
    assert listed_b.status_code == 200
    assert body["case_id"] not in [row["case_id"] for row in listed_b.json()["cases"]]


def test_session_organization_cannot_be_overridden_by_header(
    tmp_path: Path,
    monkeypatch,
):
    _clear_auth(monkeypatch)
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "organization-session-secret")
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "history.json"))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))

    org_a = CaseHistoryService(organization_id="org-a")
    org_b = CaseHistoryService(organization_id="org-b")
    a_record = _case(org_a, tmp_path / "cases", "org-a")
    _case(org_b, tmp_path / "cases", "org-b")

    client = TestClient(app)
    token = create_session_token(
        subject="admin",
        role="admin",
        organization_id="org-a",
    )
    client.cookies.set(SESSION_COOKIE_NAME, token)

    response = client.get(
        "/api/cases",
        headers={"x-breachscope-organization": "org-b"},
    )
    assert response.status_code == 200
    assert [row["case_id"] for row in response.json()["cases"]] == [a_record.case_id]
