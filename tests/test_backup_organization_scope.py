from __future__ import annotations

import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.backup_service import BackupService
from api.services.case_history import CaseHistoryService
from api.services.rule_tuning import RuleTuningProfileService


def _report(score: int) -> dict:
    return {
        "summary": {
            "total_findings": 1,
            "risk": {"score": score, "level": "medium"},
            "host_risk_summary": [
                {
                    "host": "WS-BACKUP",
                    "score": score,
                    "level": "medium",
                    "findings": 1,
                }
            ],
            "mitre_counts": {"T1059.001": 1},
        }
    }


def _case(
    service: CaseHistoryService,
    root: Path,
    name: str,
    score: int,
):
    work = root / name
    (work / "out").mkdir(parents=True, exist_ok=True)
    (work / "out" / "report.json").write_text(
        json.dumps(_report(score)),
        encoding="utf-8",
    )
    (work / "out" / "report.html").write_text(
        "<html>backup</html>",
        encoding="utf-8",
    )
    return service.register_case(work, _report(score))


def _configure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BS_API_KEY", "backup-org-api-key")
    monkeypatch.setenv("BS_DEFAULT_ORGANIZATION_ID", "default")
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )
    monkeypatch.setenv(
        "BS_RULE_TUNING_PATH",
        str(tmp_path / "rule_tuning_profiles.json"),
    )
    monkeypatch.setenv(
        "BS_RULE_AUTHORING_ROOT",
        str(tmp_path / "rule_authoring"),
    )
    monkeypatch.setenv(
        "BS_RULE_ACTIVATION_PATH",
        str(tmp_path / "rule_activation.json"),
    )
    monkeypatch.setenv("BS_BACKUP_ROOT", str(tmp_path / "backups"))
    for name in (
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
        "BS_OIDC_ISSUER_URL",
        "BS_OIDC_CLIENT_ID",
        "BS_OIDC_CLIENT_SECRET",
        "BS_OIDC_REDIRECT_URI",
    ):
        monkeypatch.delenv(name, raising=False)


def _headers(org: str) -> dict[str, str]:
    return {
        "x-api-key": "backup-org-api-key",
        "x-breachscope-organization": org,
    }


def _append_audit(path: Path, event_id: str, org: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "event_id": event_id,
        "timestamp": "2026-09-28T00:00:00Z",
        "action": "backup.scope.test",
        "status": "success",
        "organization_id": org,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


def test_backup_archive_contains_only_active_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    cases_root = tmp_path / "cases"

    org_a = CaseHistoryService(organization_id="org-a")
    org_b = CaseHistoryService(organization_id="org-b")
    case_a = _case(org_a, cases_root, "org-a-case", 41)
    case_b = _case(org_b, cases_root, "org-b-case", 77)

    unindexed = cases_root / "unindexed-unknown-owner"
    unindexed.mkdir(parents=True)
    (unindexed / "secret.txt").write_text(
        "must-not-enter-scoped-backup",
        encoding="utf-8",
    )

    audit_path = tmp_path / "audit.jsonl"
    _append_audit(audit_path, "audit-a", "org-a")
    _append_audit(audit_path, "audit-b", "org-b")

    RuleTuningProfileService(
        organization_id="org-a",
        rules_dir=Path("rules"),
    ).create_profile(
        name="Org A tuning",
        rule_include=["R-ENC"],
    )
    RuleTuningProfileService(
        organization_id="org-b",
        rules_dir=Path("rules"),
    ).create_profile(
        name="Org B tuning",
        rule_include=["R-DL"],
    )

    service = BackupService(organization_id="org-a")
    backup = service.create_backup(label="org-a-only")
    zip_path = service.backup_root / backup["filename"]

    assert backup["organization_id"] == "org-a"
    assert service.backup_root == (
        tmp_path / "backups" / "organizations" / "org-a"
    ).resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        history = json.loads(
            zf.read("case_history.json").decode("utf-8")
        )
        audit_text = zf.read("audit.jsonl").decode("utf-8")
        tuning = json.loads(
            zf.read("rule_tuning_profiles.json").decode("utf-8")
        )
        manifest = json.loads(
            zf.read("backup_manifest.json").decode("utf-8")
        )

    assert [row["case_id"] for row in history["cases"]] == [
        case_a.case_id
    ]
    assert case_b.case_id not in json.dumps(history)
    assert "cases/org-a-case/out/report.json" in names
    assert "cases/org-b-case/out/report.json" not in names
    assert not any(
        name.startswith("cases/unindexed-unknown-owner/")
        for name in names
    )

    assert "audit-a" in audit_text
    assert "audit-b" not in audit_text

    profile_names = [
        row["name"] for row in tuning["profiles"]
    ]
    assert profile_names == ["Org A tuning"]
    assert "Org B tuning" not in json.dumps(tuning)

    assert manifest["organization_id"] == "org-a"
    assert manifest["scope"] == "organization"


def test_backup_service_paths_and_lookup_are_organization_scoped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)

    default = BackupService(organization_id="default")
    org_a = BackupService(organization_id="org-a")
    org_b = BackupService(organization_id="org-b")

    assert default.backup_root == (tmp_path / "backups").resolve()
    assert org_a.backup_root == (
        tmp_path / "backups" / "organizations" / "org-a"
    ).resolve()
    assert org_b.backup_root == (
        tmp_path / "backups" / "organizations" / "org-b"
    ).resolve()

    backup = org_a.create_backup(
        include_cases=False,
        include_audit=False,
        label="org-a",
    )
    backup_id = backup["backup_id"]

    assert org_a.get_backup_path(backup_id).is_file()
    try:
        org_b.get_backup_path(backup_id)
    except KeyError:
        pass
    else:
        raise AssertionError("org-b resolved an org-a backup")

    assert org_b.list_backups() == []


def test_backup_api_blocks_cross_organization_access(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post(
        "/api/backups",
        headers=_headers("org-a"),
        params={
            "include_cases": "false",
            "include_audit": "false",
            "label": "org-a-api",
        },
    )
    assert created.status_code == 200, created.text
    backup = created.json()["backup"]
    backup_id = backup["backup_id"]
    assert backup["organization_id"] == "org-a"

    list_a = client.get(
        "/api/backups",
        headers=_headers("org-a"),
    )
    list_b = client.get(
        "/api/backups",
        headers=_headers("org-b"),
    )
    assert [row["backup_id"] for row in list_a.json()["backups"]] == [
        backup_id
    ]
    assert list_b.json()["backups"] == []

    assert client.get(
        f"/api/backups/{backup_id}/download",
        headers=_headers("org-b"),
    ).status_code == 404
    assert client.get(
        f"/api/backups/{backup_id}/integrity",
        headers=_headers("org-b"),
    ).status_code == 404
    assert client.delete(
        f"/api/backups/{backup_id}",
        headers=_headers("org-b"),
    ).status_code == 404

    download = client.get(
        f"/api/backups/{backup_id}/download",
        headers=_headers("org-a"),
    )
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/zip"

    integrity = client.get(
        f"/api/backups/{backup_id}/integrity",
        headers=_headers("org-a"),
    )
    assert integrity.status_code == 200
    assert integrity.json()["integrity"]["organization_id"] == "org-a"


def test_session_backup_scope_cannot_be_overridden_by_header(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv(
        "BS_SESSION_SECRET",
        "backup-organization-session-secret",
    )

    backup = BackupService(organization_id="org-a").create_backup(
        include_cases=False,
        include_audit=False,
        label="signed-org-a",
    )

    client = TestClient(app)
    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="admin",
            role="admin",
            organization_id="org-a",
        ),
    )

    response = client.get(
        "/api/backups",
        headers={"x-breachscope-organization": "org-b"},
    )
    assert response.status_code == 200
    assert [row["backup_id"] for row in response.json()["backups"]] == [
        backup["backup_id"]
    ]


def test_web_backup_download_uses_authenticated_fetch_and_templates_match():
    source = Path("templates/web_index.html").read_text(encoding="utf-8")
    runtime = Path(
        "breachscope/runtime_data/templates/web_index.html"
    ).read_text(encoding="utf-8")

    assert source == runtime
    assert "async function downloadBackup(backupId)" in source
    assert "data-backup-download" in source
    assert "authFetch(" in source
    forbidden = "withApiKey(" + chr(96) + "/api/backups/"
    assert forbidden not in source


def test_default_backup_excludes_non_default_authoring_namespace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)

    from api.services.rule_authoring import RuleAuthoringService

    default_authoring = RuleAuthoringService(
        organization_id="default",
        canonical_rules_dir=Path("rules"),
    )
    default_draft = default_authoring.create_draft(
        rule={
            "id": "C-BACKUP-DEFAULT",
            "name": "Default backup rule",
            "description": "default organization rule",
            "field": "command_line",
            "pattern": "default-backup-marker",
            "operator": "contains",
            "severity": "medium",
            "mitre_technique": "T1059.001",
        }
    )

    other_authoring = RuleAuthoringService(
        organization_id="org-b",
        canonical_rules_dir=Path("rules"),
    )
    other_draft = other_authoring.create_draft(
        rule={
            "id": "C-BACKUP-ORG-B",
            "name": "Org B backup rule",
            "description": "other organization rule",
            "field": "command_line",
            "pattern": "org-b-backup-marker",
            "operator": "contains",
            "severity": "medium",
            "mitre_technique": "T1059.001",
        }
    )

    service = BackupService(organization_id="default")
    backup = service.create_backup(
        include_cases=False,
        include_audit=False,
        label="default-only",
    )

    with zipfile.ZipFile(
        service.backup_root / backup["filename"],
        "r",
    ) as zf:
        names = set(zf.namelist())
        drafts = json.loads(
            zf.read("rule_authoring/drafts.json").decode("utf-8")
        )
        archive_text = "\n".join(
            zf.read(name).decode("utf-8", errors="ignore")
            for name in names
            if name.endswith((".json", ".yml", ".yaml", ".txt"))
        )

    assert [row["draft_id"] for row in drafts["drafts"]] == [
        default_draft["draft_id"]
    ]
    assert other_draft["draft_id"] not in archive_text
    assert not any(
        name.startswith("rule_authoring/organizations/")
        for name in names
    )
