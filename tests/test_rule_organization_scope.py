from __future__ import annotations

import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.backup_service import BackupService
from api.services.rule_activation import RuleActivationService
from api.services.rule_authoring import RuleAuthoringService
from api.services.rule_tuning import RuleTuningProfileService


def _rule(
    rule_id: str = "C-ORG-RULE",
    pattern: str = "organization-custom-marker-739281",
) -> dict:
    return {
        "id": rule_id,
        "name": "Organization custom rule",
        "description": "organization storage isolation test",
        "field": "command_line",
        "pattern": pattern,
        "operator": "contains",
        "severity": "high",
        "mitre_technique": "T1059.001",
    }


def _configure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BS_API_KEY", "org-rule-api-key")
    monkeypatch.setenv("BS_DEFAULT_ORGANIZATION_ID", "default")
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
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")
    monkeypatch.setenv("BS_BACKUP_ROOT", str(tmp_path / "backups"))
    for name in (
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)


def _headers(org: str) -> dict[str, str]:
    return {
        "x-api-key": "org-rule-api-key",
        "x-breachscope-organization": org,
    }


def _publish_and_activate(
    client: TestClient,
    headers: dict[str, str],
    *,
    rule_id: str,
    pattern: str,
) -> dict:
    created = client.post(
        "/api/rules/authoring/drafts",
        headers=headers,
        json={"rule": _rule(rule_id, pattern)},
    )
    assert created.status_code == 200, created.text
    draft = created.json()["draft"]

    validated = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/validate",
        headers=headers,
        json={"expected_version": 1},
    )
    assert validated.status_code == 200, validated.text

    approved = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/approve",
        headers=headers,
        json={
            "expected_version": 1,
            "review_note": "organization admin approval",
        },
    )
    assert approved.status_code == 200, approved.text

    published = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/publish",
        headers=headers,
        json={"expected_version": 1},
    )
    assert published.status_code == 200, published.text

    activated = client.post(
        "/api/rules/activation/activate",
        headers=headers,
        json={
            "expected_version": 0,
            "draft_id": draft["draft_id"],
            "published_version": 1,
        },
    )
    assert activated.status_code == 200, activated.text
    return draft


def test_rule_store_paths_are_organization_scoped_and_default_compatible(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("BS_DEFAULT_ORGANIZATION_ID", "legacy-org")
    tuning_base = tmp_path / "profiles.json"
    authoring_base = tmp_path / "authoring"
    activation_base = tmp_path / "activation.json"

    default_tuning = RuleTuningProfileService(
        path=tuning_base,
        rules_dir=Path("rules"),
        organization_id="legacy-org",
    )
    org_a_tuning = RuleTuningProfileService(
        path=tuning_base,
        rules_dir=Path("rules"),
        organization_id="org-a",
    )
    assert default_tuning.path == tuning_base.resolve()
    assert org_a_tuning.path == (
        tmp_path
        / "rule_tuning_organizations"
        / "org-a"
        / "profiles.json"
    ).resolve()

    default_authoring = RuleAuthoringService(
        root=authoring_base,
        canonical_rules_dir=Path("rules"),
        organization_id="legacy-org",
    )
    org_a_authoring = RuleAuthoringService(
        root=authoring_base,
        canonical_rules_dir=Path("rules"),
        organization_id="org-a",
    )
    assert default_authoring.root == authoring_base.resolve()
    assert org_a_authoring.root == (
        authoring_base / "organizations" / "org-a"
    ).resolve()

    default_activation = RuleActivationService(
        path=activation_base,
        authoring_root=authoring_base,
        organization_id="legacy-org",
    )
    org_a_activation = RuleActivationService(
        path=activation_base,
        authoring_root=authoring_base,
        organization_id="org-a",
    )
    assert default_activation.path == activation_base.resolve()
    assert org_a_activation.path == (
        tmp_path
        / "rule_activation_organizations"
        / "org-a"
        / "activation.json"
    ).resolve()
    assert org_a_activation.authoring.root == org_a_authoring.root

    already_scoped_authoring = RuleAuthoringService(
        root=org_a_authoring.root,
        canonical_rules_dir=Path("rules"),
        organization_id="org-a",
    )
    already_scoped_activation = RuleActivationService(
        path=org_a_activation.path,
        authoring_root=org_a_authoring.root,
        organization_id="org-a",
    )
    assert already_scoped_authoring.root == org_a_authoring.root
    assert already_scoped_activation.path == org_a_activation.path
    assert already_scoped_activation.authoring.root == org_a_authoring.root


def test_rule_tuning_api_is_organization_scoped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post(
        "/api/rules/profiles",
        headers=_headers("org-a"),
        json={
            "name": "Org A profile",
            "rule_include": ["R-ENC"],
            "rule_exclude": [],
        },
    )
    assert created.status_code == 200, created.text
    profile = created.json()["profile"]

    list_a = client.get("/api/rules/profiles", headers=_headers("org-a"))
    list_b = client.get("/api/rules/profiles", headers=_headers("org-b"))
    assert [row["profile_id"] for row in list_a.json()["profiles"]] == [
        profile["profile_id"]
    ]
    assert list_b.json()["profiles"] == []

    foreign = client.get(
        f"/api/rules/profiles/{profile['profile_id']}",
        headers=_headers("org-b"),
    )
    assert foreign.status_code == 404

    assert (
        tmp_path
        / "rule_tuning_organizations"
        / "org-a"
        / "rule_tuning_profiles.json"
    ).is_file()
    assert not (
        tmp_path
        / "rule_tuning_organizations"
        / "org-b"
        / "rule_tuning_profiles.json"
    ).exists()


def test_rule_authoring_and_activation_api_are_organization_scoped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    draft = _publish_and_activate(
        client,
        _headers("org-a"),
        rule_id="C-ORG-A",
        pattern="org-a-only-marker-918273",
    )

    list_a = client.get(
        "/api/rules/authoring/drafts",
        headers=_headers("org-a"),
    )
    list_b = client.get(
        "/api/rules/authoring/drafts",
        headers=_headers("org-b"),
    )
    assert [row["draft_id"] for row in list_a.json()["drafts"]] == [
        draft["draft_id"]
    ]
    assert list_b.json()["drafts"] == []

    foreign = client.get(
        f"/api/rules/authoring/drafts/{draft['draft_id']}",
        headers=_headers("org-b"),
    )
    assert foreign.status_code == 404

    activation_a = client.get(
        "/api/rules/activation",
        headers=_headers("org-a"),
    ).json()["activation"]
    activation_b = client.get(
        "/api/rules/activation",
        headers=_headers("org-b"),
    ).json()["activation"]
    assert activation_a["version"] == 1
    assert activation_a["active"][0]["rule_id"] == "C-ORG-A"
    assert activation_b["version"] == 0
    assert activation_b["active"] == []

    assert (
        tmp_path
        / "rule_authoring"
        / "organizations"
        / "org-a"
        / "drafts.json"
    ).is_file()
    assert (
        tmp_path
        / "rule_activation_organizations"
        / "org-a"
        / "rule_activation.json"
    ).is_file()


def test_custom_rule_analysis_loads_only_active_request_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)
    marker = "org-analysis-marker-468013"

    _publish_and_activate(
        client,
        _headers("org-a"),
        rule_id="C-ORG-ANALYSIS",
        pattern=marker,
    )

    event = {
        "timestamp": "2026-09-28T01:00:00Z",
        "host": "WS-ORG",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\analyst",
        "command_line": marker,
    }
    sample = tmp_path / "events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with sample.open("rb") as handle:
        org_b = client.post(
            "/api/analyze",
            headers=_headers("org-b"),
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "true",
                "use_custom_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "cases" / "org-b-work"),
            },
        )
    assert org_b.status_code == 200, org_b.text
    assert org_b.json()["custom_rule_activation"][
        "loaded_custom_rule_count"
    ] == 0
    assert org_b.json()["count"] == 0

    with sample.open("rb") as handle:
        org_a = client.post(
            "/api/analyze",
            headers=_headers("org-a"),
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "true",
                "use_custom_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "cases" / "org-a-work"),
            },
        )
    assert org_a.status_code == 200, org_a.text
    assert org_a.json()["custom_rule_activation"][
        "effective_custom_rule_ids"
    ] == ["C-ORG-ANALYSIS"]
    assert org_a.json()["count"] == 1


def test_session_rule_scope_cannot_be_overridden_by_header(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "rule-org-session-secret")

    RuleTuningProfileService(
        path=tmp_path / "rule_tuning_profiles.json",
        rules_dir=Path("rules"),
        organization_id="org-a",
    ).create_profile(
        name="Org A signed session",
        rule_include=["R-ENC"],
    )
    RuleTuningProfileService(
        path=tmp_path / "rule_tuning_profiles.json",
        rules_dir=Path("rules"),
        organization_id="org-b",
    ).create_profile(
        name="Org B header attempt",
        rule_include=["R-DL"],
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
        "/api/rules/profiles",
        headers={"x-breachscope-organization": "org-b"},
    )
    assert response.status_code == 200
    assert [row["name"] for row in response.json()["profiles"]] == [
        "Org A signed session"
    ]


def test_backup_contains_non_default_organization_rule_stores(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "case_history.json").write_text(
        '{"cases": []}\n',
        encoding="utf-8",
    )

    tuning = RuleTuningProfileService(
        organization_id="org-a",
        rules_dir=Path("rules"),
    )
    tuning.create_profile(
        name="Org A backup profile",
        rule_include=["R-ENC"],
    )

    authoring = RuleAuthoringService(
        organization_id="org-a",
        canonical_rules_dir=Path("rules"),
    )
    draft = authoring.create_draft(
        rule=_rule("C-ORG-BACKUP", "org-backup-marker"),
    )
    authoring.validate_draft(draft["draft_id"], expected_version=1)
    authoring.approve_draft(
        draft["draft_id"],
        expected_version=1,
        review_note="backup approval",
        approved_by="admin",
    )
    published = authoring.publish_draft(
        draft["draft_id"],
        expected_version=1,
        published_by="admin",
    )

    activation = RuleActivationService(organization_id="org-a")
    activation.activate(
        draft_id=draft["draft_id"],
        published_version=1,
        expected_version=0,
        actor="admin",
    )

    backup_root = tmp_path / "backups"
    backup = BackupService(
        backup_root=backup_root,
        organization_id="org-a",
    ).create_backup(
        include_cases=False,
        include_audit=False,
        label="organization-rule-stores",
    )

    publication = published["publications"][-1]
    zip_path = (
        backup_root
        / "organizations"
        / "org-a"
        / backup["filename"]
    )
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        manifest = json.loads(
            zf.read("backup_manifest.json").decode("utf-8")
        )

    assert backup["organization_id"] == "org-a"
    assert manifest["organization_id"] == "org-a"
    assert "rule_tuning_profiles.json" in names
    assert "rule_authoring/drafts.json" in names
    assert (
        "rule_authoring/" + publication["relative_path"]
    ) in names
    assert "rule_activation.json" in names


def test_same_custom_rule_id_can_be_independently_active_per_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)
    shared_rule_id = "C-ORG-SHARED-ID"

    draft_a = _publish_and_activate(
        client,
        _headers("org-a"),
        rule_id=shared_rule_id,
        pattern="shared-id-org-a-marker",
    )
    draft_b = _publish_and_activate(
        client,
        _headers("org-b"),
        rule_id=shared_rule_id,
        pattern="shared-id-org-b-marker",
    )

    assert draft_a["draft_id"] != draft_b["draft_id"]

    state_a = client.get(
        "/api/rules/activation",
        headers=_headers("org-a"),
    ).json()["activation"]
    state_b = client.get(
        "/api/rules/activation",
        headers=_headers("org-b"),
    ).json()["activation"]
    assert [row["rule_id"] for row in state_a["active"]] == [shared_rule_id]
    assert [row["rule_id"] for row in state_b["active"]] == [shared_rule_id]
    assert state_a["active"][0]["draft_id"] == draft_a["draft_id"]
    assert state_b["active"][0]["draft_id"] == draft_b["draft_id"]
