from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services.audit_log import AuditLogService
from api.services.backup_service import BackupService
from api.services.rule_authoring import (
    RuleAuthoringError,
    RuleAuthoringService,
    RuleAuthoringStateError,
    RuleAuthoringVersionConflict,
)
from api.services.rule_tuning import RuleTuningProfileService
from breachscope.rules import load_rules


client = TestClient(app)


def _service(tmp_path: Path) -> RuleAuthoringService:
    return RuleAuthoringService(
        root=tmp_path / "authoring",
        canonical_rules_dir=Path("rules"),
    )


def _rule(rule_id: str = "C-TEST-POWERSHELL") -> dict:
    return {
        "id": rule_id,
        "name": "Custom PowerShell Marker",
        "description": "Authoring workflow test",
        "field": "command_line",
        "pattern": "custom-marker",
        "operator": "contains",
        "severity": "high",
        "mitre_technique": "T1059.001",
    }


def test_authoring_full_flow_publishes_separate_loadable_yaml(tmp_path: Path) -> None:
    service = _service(tmp_path)

    created = service.create_draft(rule=_rule(), updated_by="alice")
    assert created["status"] == "draft"
    assert created["version"] == 1
    assert created["revision_count"] == 1
    assert created["publications"] == []

    validated = service.validate_draft(
        created["draft_id"], expected_version=1
    )
    assert validated["status"] == "validated"
    assert validated["validation"]["status"] == "pass"
    assert validated["validation"]["version"] == 1
    assert validated["validation"]["canonical_rulepack_modified"] is False

    approved = service.approve_draft(
        created["draft_id"],
        expected_version=1,
        review_note="Reviewed field, operator, ATT&CK mapping, and expected match scope.",
        approved_by="reviewer",
    )
    assert approved["status"] == "approved"
    assert approved["approval"]["version"] == 1
    assert approved["approval"]["approved_by"] == "reviewer"

    published = service.publish_draft(
        created["draft_id"],
        expected_version=1,
        published_by="publisher",
    )
    assert published["status"] == "published"
    assert len(published["publications"]) == 1
    publication = published["publications"][0]
    assert publication["activated_in_detector"] is False

    artifact = service.root / publication["relative_path"]
    assert artifact.exists()
    assert artifact.is_file()
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == publication["sha256"]
    assert service.canonical_rules_dir not in artifact.parents

    loaded = load_rules(artifact.parent)
    assert len(loaded) == 1
    assert loaded[0].id == "C-TEST-POWERSHELL"
    assert loaded[0].operator == "contains"


def test_authoring_requires_validate_and_approve_before_publish(tmp_path: Path) -> None:
    service = _service(tmp_path)
    created = service.create_draft(rule=_rule())

    with pytest.raises(RuleAuthoringStateError):
        service.approve_draft(
            created["draft_id"],
            expected_version=1,
            review_note="too early",
            approved_by="reviewer",
        )

    with pytest.raises(RuleAuthoringStateError):
        service.publish_draft(
            created["draft_id"],
            expected_version=1,
            published_by="publisher",
        )

    service.validate_draft(created["draft_id"], expected_version=1)

    with pytest.raises(RuleAuthoringStateError):
        service.publish_draft(
            created["draft_id"],
            expected_version=1,
            published_by="publisher",
        )


def test_authoring_update_resets_validation_and_approval(tmp_path: Path) -> None:
    service = _service(tmp_path)
    created = service.create_draft(rule=_rule(), updated_by="alice")
    service.validate_draft(created["draft_id"], expected_version=1)
    service.approve_draft(
        created["draft_id"],
        expected_version=1,
        review_note="v1 approved",
        approved_by="reviewer",
    )

    changed = _rule()
    changed["pattern"] = "custom-marker-v2"
    updated = service.update_draft(
        created["draft_id"],
        expected_version=1,
        rule=changed,
        updated_by="alice",
    )

    assert updated["version"] == 2
    assert updated["status"] == "draft"
    assert updated["validation"] is None
    assert updated["approval"] is None
    assert updated["revision_count"] == 2

    with pytest.raises(RuleAuthoringVersionConflict):
        service.update_draft(
            created["draft_id"],
            expected_version=1,
            rule=changed,
        )


def test_authoring_runtime_validation_rejects_invalid_regex_and_canonical_collision(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)

    invalid = _rule("C-INVALID-REGEX")
    invalid["operator"] = "regex"
    invalid["pattern"] = "("
    draft = service.create_draft(rule=invalid)
    with pytest.raises(RuleAuthoringError, match="runtime rule validation failed"):
        service.validate_draft(draft["draft_id"], expected_version=1)

    collision = service.create_draft(rule=_rule("R-ENC"))
    with pytest.raises(RuleAuthoringError, match="canonical rule ID"):
        service.validate_draft(collision["draft_id"], expected_version=1)


def test_authoring_rejects_second_published_owner_for_same_rule_id(tmp_path: Path) -> None:
    service = _service(tmp_path)

    first = service.create_draft(rule=_rule("C-DUPLICATE"))
    service.validate_draft(first["draft_id"], expected_version=1)
    service.approve_draft(
        first["draft_id"],
        expected_version=1,
        review_note="first owner",
        approved_by="reviewer",
    )
    service.publish_draft(
        first["draft_id"],
        expected_version=1,
        published_by="publisher",
    )

    second = service.create_draft(rule=_rule("C-DUPLICATE"))
    service.validate_draft(second["draft_id"], expected_version=1)
    service.approve_draft(
        second["draft_id"],
        expected_version=1,
        review_note="second owner",
        approved_by="reviewer",
    )
    with pytest.raises(RuleAuthoringError, match="이미 다른 custom draft"):
        service.publish_draft(
            second["draft_id"],
            expected_version=1,
            published_by="publisher",
        )


def test_authoring_corrupt_store_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "authoring"
    root.mkdir()
    index = root / "drafts.json"
    index.write_text("{broken", encoding="utf-8")
    before = index.read_bytes()
    service = RuleAuthoringService(root=root, canonical_rules_dir=Path("rules"))

    with pytest.raises(RuleAuthoringError, match="읽을 수 없습니다"):
        service.list_drafts()
    with pytest.raises(RuleAuthoringError):
        service.create_draft(rule=_rule())

    assert index.read_bytes() == before


def test_authoring_api_flow_and_audit(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "authoring"
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("BS_RULE_AUTHORING_ROOT", str(root))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(audit))
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")

    create = client.post(
        "/api/rules/authoring/drafts",
        json={"rule": _rule("C-API-AUTHOR")},
    )
    assert create.status_code == 200
    draft = create.json()["draft"]
    assert draft["status"] == "draft"

    premature = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/publish",
        json={"expected_version": 1},
    )
    assert premature.status_code == 409

    validate = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/validate",
        json={"expected_version": 1},
    )
    assert validate.status_code == 200
    assert validate.json()["draft"]["status"] == "validated"

    approve = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/approve",
        json={
            "expected_version": 1,
            "review_note": "Reviewed for controlled custom publication.",
        },
    )
    assert approve.status_code == 200
    assert approve.json()["draft"]["status"] == "approved"

    publish = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/publish",
        json={"expected_version": 1},
    )
    assert publish.status_code == 200
    body = publish.json()["draft"]
    assert body["status"] == "published"
    assert body["publications"][-1]["activated_in_detector"] is False

    canonical = client.get("/api/rules")
    assert canonical.status_code == 200
    canonical_payload = canonical.json()
    assert canonical_payload["count"] == 73
    assert "C-API-AUTHOR" not in {row["id"] for row in canonical_payload["rules"]}

    detail = client.get(
        f"/api/rules/authoring/drafts/{draft['draft_id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["draft"]["revision_count"] == 1

    actions = {
        row["action"]
        for row in AuditLogService(path=audit).read_events(limit=50)
    }
    assert {
        "rule.authoring.create",
        "rule.authoring.validate",
        "rule.authoring.approve",
        "rule.authoring.publish",
    }.issubset(actions)


def test_authoring_api_version_conflict(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BS_RULE_AUTHORING_ROOT", str(tmp_path / "authoring"))

    create = client.post(
        "/api/rules/authoring/drafts",
        json={"rule": _rule("C-API-CONFLICT")},
    )
    draft = create.json()["draft"]

    update = client.put(
        f"/api/rules/authoring/drafts/{draft['draft_id']}",
        json={
            "expected_version": 1,
            "rule": {**_rule("C-API-CONFLICT"), "pattern": "v2-marker"},
        },
    )
    assert update.status_code == 200
    assert update.json()["draft"]["version"] == 2

    stale = client.post(
        f"/api/rules/authoring/drafts/{draft['draft_id']}/validate",
        json={"expected_version": 1},
    )
    assert stale.status_code == 409


def test_authoring_web_ui_exposes_controlled_workflow() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert 'id="ruleDraftSelect"' in response.text
    assert 'id="authorRuleId"' in response.text
    assert 'id="authorRulePattern"' in response.text
    assert 'id="authorReviewNote"' in response.text
    assert 'id="validateRuleDraftBtn"' in response.text
    assert 'id="approveRuleDraftBtn"' in response.text
    assert 'id="publishRuleDraftBtn"' in response.text
    assert "/api/rules/authoring/drafts" in response.text
    assert "canonical 73-rule detector에는 자동 활성화되지 않습니다" in response.text


def test_backup_includes_rule_tuning_and_authoring_artifacts(tmp_path: Path, monkeypatch) -> None:
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    history_path = tmp_path / "case_history.json"
    history_path.write_text('{"cases": []}\n', encoding="utf-8")
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text("", encoding="utf-8")
    tuning_path = tmp_path / "rule_tuning_profiles.json"
    authoring_root = tmp_path / "rule_authoring"
    backup_root = tmp_path / "backups"

    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(history_path))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(audit_path))
    monkeypatch.setenv("BS_RULE_TUNING_PATH", str(tuning_path))
    monkeypatch.setenv("BS_RULE_AUTHORING_ROOT", str(authoring_root))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(backup_root))

    tuning = RuleTuningProfileService(path=tuning_path, rules_dir=Path("rules"))
    tuning.create_profile(name="backup-profile", rule_exclude=["R-ENC"])

    authoring = RuleAuthoringService(
        root=authoring_root,
        canonical_rules_dir=Path("rules"),
    )
    draft = authoring.create_draft(rule=_rule("C-BACKUP-RULE"))
    authoring.validate_draft(draft["draft_id"], expected_version=1)
    authoring.approve_draft(
        draft["draft_id"],
        expected_version=1,
        review_note="backup coverage",
        approved_by="reviewer",
    )
    published = authoring.publish_draft(
        draft["draft_id"],
        expected_version=1,
        published_by="publisher",
    )
    publication = published["publications"][-1]

    backup = BackupService(backup_root=backup_root).create_backup(
        include_cases=False,
        include_audit=False,
        label="rule-config-backup",
    )
    zip_path = backup_root / backup["filename"]
    assert zip_path.exists()

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        assert "rule_tuning_profiles.json" in names
        assert "rule_authoring/drafts.json" in names
        expected_pub = "rule_authoring/" + publication["relative_path"]
        assert expected_pub in names
        manifest = json.loads(zf.read("backup_manifest.json").decode("utf-8"))

    source_paths = manifest["sources"]
    assert source_paths["rule_tuning_path"] == str(tuning_path.resolve())
    assert source_paths["rule_authoring_root"] == str(authoring_root.resolve())
