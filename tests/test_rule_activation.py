from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services.audit_log import AuditLogService
from api.services.rule_activation import (
    RuleActivationError,
    RuleActivationService,
    RuleActivationVersionConflict,
)
from api.services.rule_authoring import RuleAuthoringService


client = TestClient(app)


def _rule(rule_id: str = "C-ACTIVATION-TEST", pattern: str = "zz-custom-activation-marker-982734") -> dict:
    return {
        "id": rule_id,
        "name": "Custom activation test",
        "description": "activation workflow test",
        "field": "command_line",
        "pattern": pattern,
        "operator": "contains",
        "severity": "high",
        "mitre_technique": "T1059.001",
    }


def _published(
    tmp_path: Path,
    *,
    rule_id: str = "C-ACTIVATION-TEST",
    pattern: str = "zz-custom-activation-marker-982734",
) -> tuple[RuleAuthoringService, dict]:
    authoring = RuleAuthoringService(
        root=tmp_path / "authoring",
        canonical_rules_dir=Path("rules"),
    )
    draft = authoring.create_draft(rule=_rule(rule_id, pattern), updated_by="alice")
    authoring.validate_draft(draft["draft_id"], expected_version=1)
    authoring.approve_draft(
        draft["draft_id"],
        expected_version=1,
        review_note="approved for activation test",
        approved_by="reviewer",
    )
    published = authoring.publish_draft(
        draft["draft_id"],
        expected_version=1,
        published_by="publisher",
    )
    return authoring, published


def test_activation_versioned_rollout_and_rollback(tmp_path: Path) -> None:
    authoring, published_v1 = _published(tmp_path)
    service = RuleActivationService(
        path=tmp_path / "activation.json",
        authoring_root=authoring.root,
    )

    initial = service.get_state()
    assert initial["version"] == 0
    assert initial["active"] == []

    draft_id = published_v1["draft_id"]
    active_v1 = service.activate(
        draft_id=draft_id,
        published_version=1,
        expected_version=0,
        actor="operator",
    )
    assert active_v1["version"] == 1
    assert active_v1["active"][0]["published_version"] == 1

    rules, provenance = service.load_active_rules()
    assert [r.id for r in rules] == ["C-ACTIVATION-TEST"]
    assert provenance[0]["published_version"] == 1

    updated_rule = _rule(pattern="zz-custom-activation-marker-v2-982734")
    updated = authoring.update_draft(
        draft_id,
        expected_version=1,
        rule=updated_rule,
        updated_by="alice",
    )
    assert updated["version"] == 2
    authoring.validate_draft(draft_id, expected_version=2)
    authoring.approve_draft(
        draft_id,
        expected_version=2,
        review_note="approved v2",
        approved_by="reviewer",
    )
    authoring.publish_draft(
        draft_id,
        expected_version=2,
        published_by="publisher",
    )

    active_v2 = service.activate(
        draft_id=draft_id,
        published_version=2,
        expected_version=1,
        actor="operator",
    )
    assert active_v2["version"] == 2
    assert active_v2["active"][0]["published_version"] == 2

    rolled_back = service.rollback(
        target_version=1,
        expected_version=2,
        actor="operator",
    )
    assert rolled_back["version"] == 3
    assert rolled_back["active"][0]["published_version"] == 1
    assert rolled_back["history"][-1]["reason"] == "rollback to activation version 1"

    rules, _ = service.load_active_rules()
    assert rules[0].pattern == "zz-custom-activation-marker-982734"

    deactivated = service.deactivate(
        draft_id=draft_id,
        expected_version=3,
        actor="operator",
    )
    assert deactivated["version"] == 4
    assert deactivated["active"] == []

    with pytest.raises(RuleActivationVersionConflict):
        service.activate(
            draft_id=draft_id,
            published_version=2,
            expected_version=3,
        )


def test_activation_rejects_unpublished_or_tampered_artifact(tmp_path: Path) -> None:
    authoring, published = _published(tmp_path, rule_id="C-ACTIVATION-TAMPER")
    service = RuleActivationService(
        path=tmp_path / "activation.json",
        authoring_root=authoring.root,
    )

    with pytest.raises(RuleActivationError, match="publish artifact"):
        service.activate(
            draft_id=published["draft_id"],
            published_version=99,
            expected_version=0,
        )

    state = service.activate(
        draft_id=published["draft_id"],
        published_version=1,
        expected_version=0,
    )
    assert state["version"] == 1

    publication = published["publications"][-1]
    artifact = authoring.root / publication["relative_path"]
    artifact.write_text(artifact.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")

    with pytest.raises(RuleActivationError, match="SHA-256"):
        service.load_active_rules()


def test_activation_api_and_audit(tmp_path: Path, monkeypatch) -> None:
    authoring, published = _published(tmp_path, rule_id="C-ACTIVATION-API")
    activation_path = tmp_path / "activation.json"
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("BS_RULE_AUTHORING_ROOT", str(authoring.root))
    monkeypatch.setenv("BS_RULE_ACTIVATION_PATH", str(activation_path))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(audit_path))
    monkeypatch.setenv("BS_AUDIT_ENABLED", "1")

    initial = client.get("/api/rules/activation")
    assert initial.status_code == 200
    assert initial.json()["activation"]["version"] == 0

    activated = client.post(
        "/api/rules/activation/activate",
        json={
            "expected_version": 0,
            "draft_id": published["draft_id"],
            "published_version": 1,
        },
    )
    assert activated.status_code == 200
    state = activated.json()["activation"]
    assert state["version"] == 1
    assert state["active"][0]["rule_id"] == "C-ACTIVATION-API"

    stale = client.post(
        "/api/rules/activation/deactivate",
        json={"expected_version": 0, "draft_id": published["draft_id"]},
    )
    assert stale.status_code == 409

    rolled = client.post(
        "/api/rules/activation/rollback",
        json={"expected_version": 1, "target_version": 0},
    )
    assert rolled.status_code == 200
    assert rolled.json()["activation"]["version"] == 2
    assert rolled.json()["activation"]["active"] == []

    actions = {
        row["action"]
        for row in AuditLogService(path=audit_path).read_events(limit=30)
    }
    assert "rule.activation.activate" in actions
    assert "rule.activation.rollback" in actions


def test_analysis_custom_rules_are_opt_in_and_report_evidence_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    authoring, published = _published(tmp_path, rule_id="C-ANALYSIS-OPTIN")
    activation_path = tmp_path / "activation.json"
    activation = RuleActivationService(
        path=activation_path,
        authoring_root=authoring.root,
    )
    activation.activate(
        draft_id=published["draft_id"],
        published_version=1,
        expected_version=0,
    )

    monkeypatch.setenv("BS_RULE_AUTHORING_ROOT", str(authoring.root))
    monkeypatch.setenv("BS_RULE_ACTIVATION_PATH", str(activation_path))
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path))

    event = {
        "timestamp": "2026-09-26T12:00:00Z",
        "host": "WS-CUSTOM",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\analyst",
        "command_line": "zz-custom-activation-marker-982734",
    }
    sample = tmp_path / "custom-events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with sample.open("rb") as handle:
        off = client.post(
            "/api/analyze",
            files=[("files", ("events.jsonl", handle, "application/octet-stream"))],
            data={
                "use_repo_rules": "true",
                "use_custom_rules": "false",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "off-work"),
            },
        )
    assert off.status_code == 200
    off_body = off.json()
    assert off_body["count"] == 0
    assert off_body["preview"]["rule_pack"]["total_rules"] == 73
    assert off_body["custom_rule_activation"]["enabled_for_analysis"] is False
    assert off_body["custom_rule_activation"]["loaded_custom_rule_count"] == 0

    with sample.open("rb") as handle:
        on = client.post(
            "/api/analyze",
            files=[("files", ("events.jsonl", handle, "application/octet-stream"))],
            data={
                "use_repo_rules": "true",
                "use_custom_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(tmp_path / "on-work"),
            },
        )
    assert on.status_code == 200
    on_body = on.json()
    assert on_body["count"] == 1
    assert on_body["preview"]["rule_pack"]["total_rules"] == 74
    custom = on_body["custom_rule_activation"]
    assert custom["enabled_for_analysis"] is True
    assert custom["loaded_custom_rule_count"] == 1
    assert custom["effective_custom_rule_ids"] == ["C-ANALYSIS-OPTIN"]
    assert custom["canonical_rulepack_modified"] is False
    assert custom["current_detection_evidence_applies_to_custom_rules"] is False

    report = json.loads(Path(on_body["json_path"]).read_text(encoding="utf-8"))
    report_custom = report["summary"]["custom_rule_activation"]
    assert report_custom["provenance"][0]["rule_id"] == "C-ANALYSIS-OPTIN"
    assert report["summary"]["rule_pack"]["total_rules"] == 74


def test_web_ui_exposes_activation_controls_and_opt_in() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="useCustomRules"' in response.text
    assert 'id="refreshRuleActivationBtn"' in response.text
    assert 'id="activateRuleDraftBtn"' in response.text
    assert 'id="deactivateRuleDraftBtn"' in response.text
    assert 'id="ruleActivationHistory"' in response.text
    assert "/api/rules/activation/rollback" in response.text
    assert "fd.append('use_custom_rules'" in response.text
    assert "기본 OFF" in response.text
