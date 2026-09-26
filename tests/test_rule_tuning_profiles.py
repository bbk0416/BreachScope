from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services.audit_log import AuditLogService
from api.services.rule_tuning import (
    RuleTuningProfileError,
    RuleTuningProfileService,
    RuleTuningVersionConflict,
)


client = TestClient(app)


def _service(tmp_path: Path) -> RuleTuningProfileService:
    return RuleTuningProfileService(path=tmp_path / "profiles.json", rules_dir=Path("rules"))


def test_profile_create_update_history_and_delete(tmp_path: Path) -> None:
    service = _service(tmp_path)

    created = service.create_profile(
        name="PowerShell triage",
        description="Initial analyst tuning",
        rule_include=["r-enc"],
        rule_exclude=["R-WMI-Create"],
        updated_by="alice",
    )
    assert created["version"] == 1
    assert created["rule_include"] == ["R-ENC"]
    assert created["rule_exclude"] == ["R-WMI-Create"]
    assert created["revision_count"] == 1
    assert created["revisions"][0]["updated_by"] == "alice"

    listed = service.list_profiles()
    assert len(listed) == 1
    assert "revisions" not in listed[0]
    assert listed[0]["revision_count"] == 1

    updated = service.update_profile(
        created["profile_id"],
        expected_version=1,
        name="PowerShell triage",
        description="Second analyst tuning",
        rule_include=["R-ENC", "R-DL"],
        rule_exclude=[],
        updated_by="bob",
    )
    assert updated["version"] == 2
    assert updated["revision_count"] == 2
    assert [row["version"] for row in updated["revisions"]] == [1, 2]
    assert updated["revisions"][0]["rule_exclude"] == ["R-WMI-Create"]
    assert updated["revisions"][1]["rule_include"] == ["R-ENC", "R-DL"]

    with pytest.raises(RuleTuningVersionConflict):
        service.update_profile(
            created["profile_id"],
            expected_version=1,
            name="stale",
            rule_include=[],
            rule_exclude=[],
        )

    with pytest.raises(RuleTuningVersionConflict):
        service.delete_profile(created["profile_id"], expected_version=1)

    removed = service.delete_profile(created["profile_id"], expected_version=2)
    assert removed["version"] == 2
    assert service.list_profiles() == []


def test_profile_rejects_unknown_and_overlapping_rule_ids(tmp_path: Path) -> None:
    service = _service(tmp_path)

    with pytest.raises(RuleTuningProfileError, match="존재하지 않는 룰 ID"):
        service.create_profile(name="bad", rule_include=["R-NOT-FOUND"])

    with pytest.raises(RuleTuningProfileError, match="동시에"):
        service.create_profile(
            name="overlap",
            rule_include=["R-ENC"],
            rule_exclude=["r-enc"],
        )

    assert not service.path.exists()


def test_profile_store_corruption_fails_closed_without_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text("{not-json", encoding="utf-8")
    before = path.read_bytes()
    service = RuleTuningProfileService(path=path, rules_dir=Path("rules"))

    with pytest.raises(RuleTuningProfileError, match="읽을 수 없습니다"):
        service.list_profiles()
    with pytest.raises(RuleTuningProfileError):
        service.create_profile(name="must-not-overwrite")

    assert path.read_bytes() == before


def test_profile_api_crud_version_conflict_and_audit(tmp_path: Path, monkeypatch) -> None:
    profile_path = tmp_path / "profiles.json"
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("BS_RULE_TUNING_PATH", str(profile_path))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(audit_path))
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")

    create = client.post(
        "/api/rules/profiles",
        json={
            "name": "Customer A",
            "description": "Per-analysis exclusions",
            "rule_include": ["R-ENC"],
            "rule_exclude": ["R-WMI-Create"],
        },
    )
    assert create.status_code == 200
    profile = create.json()["profile"]
    assert profile["version"] == 1

    listing = client.get("/api/rules/profiles")
    assert listing.status_code == 200
    assert listing.json()["profiles"][0]["profile_id"] == profile["profile_id"]

    detail = client.get(f"/api/rules/profiles/{profile['profile_id']}")
    assert detail.status_code == 200
    assert detail.json()["profile"]["revision_count"] == 1

    stale = client.put(
        f"/api/rules/profiles/{profile['profile_id']}",
        json={
            "expected_version": 99,
            "name": "Customer A",
            "description": "stale",
            "rule_include": ["R-ENC"],
            "rule_exclude": [],
        },
    )
    assert stale.status_code == 409

    update = client.put(
        f"/api/rules/profiles/{profile['profile_id']}",
        json={
            "expected_version": 1,
            "name": "Customer A",
            "description": "v2",
            "rule_include": ["R-ENC", "R-DL"],
            "rule_exclude": [],
        },
    )
    assert update.status_code == 200
    assert update.json()["profile"]["version"] == 2
    assert update.json()["profile"]["revision_count"] == 2

    stale_delete = client.delete(
        f"/api/rules/profiles/{profile['profile_id']}",
        params={"expected_version": 1},
    )
    assert stale_delete.status_code == 409

    deleted = client.delete(
        f"/api/rules/profiles/{profile['profile_id']}",
        params={"expected_version": 2},
    )
    assert deleted.status_code == 200

    actions = [
        row["action"]
        for row in AuditLogService(path=audit_path).read_events(limit=20)
    ]
    assert "rule.profile.create" in actions
    assert "rule.profile.update" in actions
    assert "rule.profile.delete" in actions


def test_profile_api_rejects_invalid_rule_sets(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BS_RULE_TUNING_PATH", str(tmp_path / "profiles.json"))

    unknown = client.post(
        "/api/rules/profiles",
        json={"name": "bad", "rule_include": ["R-NOT-FOUND"]},
    )
    assert unknown.status_code == 400

    overlap = client.post(
        "/api/rules/profiles",
        json={
            "name": "overlap",
            "rule_include": ["R-ENC"],
            "rule_exclude": ["R-ENC"],
        },
    )
    assert overlap.status_code == 400


def test_web_ui_exposes_versioned_rule_tuning_profiles() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert 'id="ruleProfileSelect"' in response.text
    assert 'id="ruleProfileName"' in response.text
    assert 'id="ruleProfileHistory"' in response.text
    assert 'id="saveRuleProfileBtn"' in response.text
    assert 'id="deleteRuleProfileBtn"' in response.text
    assert "/api/rules/profiles" in response.text
    assert "expected_version" in response.text
    assert "이 버전 불러오기" in response.text
    assert "canonical rules/" in response.text
