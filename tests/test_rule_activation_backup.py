from __future__ import annotations

import json
import zipfile
from pathlib import Path

from api.services.backup_service import BackupService
from api.services.rule_activation import RuleActivationService
from api.services.rule_authoring import RuleAuthoringService


def _rule() -> dict:
    return {
        "id": "C-ACTIVATION-BACKUP",
        "name": "Activation backup rule",
        "description": "backup coverage",
        "field": "command_line",
        "pattern": "activation-backup-marker",
        "operator": "contains",
        "severity": "medium",
        "mitre_technique": "T1059.001",
    }


def test_backup_contains_activation_manifest_and_published_artifact(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    history_path = tmp_path / "case_history.json"
    history_path.write_text('{"cases": []}\n', encoding="utf-8")
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text("", encoding="utf-8")
    authoring_root = tmp_path / "rule_authoring"
    activation_path = tmp_path / "rule_activation.json"
    backup_root = tmp_path / "backups"

    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(history_path))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(audit_path))
    monkeypatch.setenv("BS_RULE_AUTHORING_ROOT", str(authoring_root))
    monkeypatch.setenv("BS_RULE_ACTIVATION_PATH", str(activation_path))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(backup_root))

    authoring = RuleAuthoringService(
        root=authoring_root,
        canonical_rules_dir=Path("rules"),
    )
    draft = authoring.create_draft(rule=_rule())
    authoring.validate_draft(draft["draft_id"], expected_version=1)
    authoring.approve_draft(
        draft["draft_id"],
        expected_version=1,
        review_note="backup activation approved",
        approved_by="reviewer",
    )
    published = authoring.publish_draft(
        draft["draft_id"],
        expected_version=1,
        published_by="publisher",
    )

    activation = RuleActivationService(
        path=activation_path,
        authoring_root=authoring_root,
    )
    state = activation.activate(
        draft_id=draft["draft_id"],
        published_version=1,
        expected_version=0,
        actor="operator",
    )
    assert state["version"] == 1
    assert activation_path.exists()

    backup = BackupService(backup_root=backup_root).create_backup(
        include_cases=False,
        include_audit=False,
        label="activation-backup",
    )
    zip_path = backup_root / backup["filename"]

    publication = published["publications"][-1]
    expected_pub = "rule_authoring/" + publication["relative_path"]

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        assert "rule_activation.json" in names
        assert "rule_authoring/drafts.json" in names
        assert expected_pub in names

        activation_copy = json.loads(
            zf.read("rule_activation.json").decode("utf-8")
        )
        assert activation_copy["version"] == 1
        assert activation_copy["active"][0]["rule_id"] == "C-ACTIVATION-BACKUP"

        manifest = json.loads(
            zf.read("backup_manifest.json").decode("utf-8")
        )

    assert manifest["sources"]["rule_activation_path"] == str(
        activation_path.resolve()
    )
