from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from api.services.scim_migration import (
    ScimMigrationError,
    ScimStoreConfig,
    migrate_scim_identity_store,
    read_identity_snapshot,
)
from api.services.scim_store import (
    ScimIdentityStore,
    ScimStoreError,
)


def _config(
    root: Path,
    backend: str,
    *,
    database_url: str = "",
) -> ScimStoreConfig:
    return ScimStoreConfig(
        backend=backend,
        user_path=root / "users.json",
        group_path=root / "groups.json",
        database_path=root / "identity.db",
        database_url=database_url,
    )


def _users() -> list[dict]:
    return [
        {
            "id": "u-1",
            "userName": "operator@example.test",
            "externalId": "oidc-subject-1",
            "active": True,
            "role": "",
            "organization_id": "",
            "created": "2026-09-29T01:00:00+00:00",
            "last_modified": "2026-09-29T01:00:00+00:00",
        },
        {
            "id": "u-2",
            "userName": "staged@example.test",
            "externalId": "",
            "active": False,
            "role": "",
            "organization_id": "",
            "created": "2026-09-29T01:01:00+00:00",
            "last_modified": "2026-09-29T01:01:00+00:00",
        },
    ]


def _groups() -> list[dict]:
    return [
        {
            "id": "g-child",
            "displayName": "Child",
            "member_ids": ["u-1"],
            "role": "",
            "organization_id": "",
            "created": "2026-09-29T01:02:00+00:00",
            "last_modified": "2026-09-29T01:02:00+00:00",
        },
        {
            "id": "g-operators",
            "displayName": "Operators",
            "member_ids": ["g-child"],
            "role": "operator",
            "organization_id": "org-a",
            "created": "2026-09-29T01:03:00+00:00",
            "last_modified": "2026-09-29T01:03:00+00:00",
        },
    ]


def _seed(
    config: ScimStoreConfig,
    *,
    users: list[dict] | None = None,
    groups: list[dict] | None = None,
) -> None:
    store = config.build()
    with store.mutation():
        store.save_users(users if users is not None else _users())
        store.save_groups(groups if groups is not None else _groups())


def test_migrate_json_to_sqlite_preserves_source_and_verifies(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "source", "json")
    target = _config(tmp_path / "target", "sqlite")
    _seed(source)

    source_user_bytes = source.user_path.read_bytes()
    source_group_bytes = source.group_path.read_bytes()

    result = migrate_scim_identity_store(
        source,
        target,
    )

    assert result["success"] is True
    assert result["verified"] is True
    assert result["dry_run"] is False
    assert result["source_backend"] == "json"
    assert result["target_backend"] == "sqlite"
    assert result["users"] == 2
    assert result["groups"] == 2
    assert result["source_sha256"] == result["target_sha256"]
    assert result["backup_path"] is None

    users, groups = read_identity_snapshot(target.build())
    assert {row["id"] for row in users} == {"u-1", "u-2"}
    assert {row["id"] for row in groups} == {
        "g-child",
        "g-operators",
    }
    assert source.user_path.read_bytes() == source_user_bytes
    assert source.group_path.read_bytes() == source_group_bytes


def test_dry_run_validates_without_creating_target(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "source", "json")
    target = _config(tmp_path / "target", "sqlite")
    _seed(source)

    result = migrate_scim_identity_store(
        source,
        target,
        dry_run=True,
    )

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["verified"] is False
    assert not target.database_path.exists()


def test_nonempty_target_requires_replace(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "source", "json")
    target = _config(tmp_path / "target", "sqlite")
    _seed(source)
    _seed(
        target,
        users=[
            {
                **_users()[0],
                "id": "old-user",
                "userName": "old@example.test",
                "externalId": "old-subject",
            }
        ],
        groups=[],
    )

    with pytest.raises(
        ScimMigrationError,
        match="not empty",
    ):
        migrate_scim_identity_store(
            source,
            target,
        )

    users, _ = read_identity_snapshot(target.build())
    assert [row["id"] for row in users] == ["old-user"]


def test_replace_creates_snapshot_backup(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "source", "sqlite")
    target = _config(tmp_path / "target", "json")
    backups = tmp_path / "backups"
    _seed(source)
    old_users = [
        {
            **_users()[0],
            "id": "old-user",
            "userName": "old@example.test",
            "externalId": "old-subject",
        }
    ]
    _seed(target, users=old_users, groups=[])

    result = migrate_scim_identity_store(
        source,
        target,
        replace=True,
        backup_dir=backups,
    )

    assert result["verified"] is True
    backup_path = Path(result["backup_path"])
    assert backup_path.exists()
    payload = json.loads(backup_path.read_text(encoding="utf-8"))
    assert payload["backend"] == "json"
    assert [row["id"] for row in payload["users"]] == [
        "old-user"
    ]
    assert payload["groups"] == []

    users, groups = read_identity_snapshot(target.build())
    assert {row["id"] for row in users} == {"u-1", "u-2"}
    assert {row["id"] for row in groups} == {
        "g-child",
        "g-operators",
    }


def test_same_store_is_rejected(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "same", "json")
    _seed(source)

    with pytest.raises(
        ScimMigrationError,
        match="same",
    ):
        migrate_scim_identity_store(
            source,
            source,
        )


def test_invalid_nested_group_source_is_rejected_before_target_write(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "source", "json")
    target = _config(tmp_path / "target", "sqlite")
    cycle = [
        {
            **_groups()[0],
            "id": "g-a",
            "displayName": "A",
            "member_ids": ["g-b"],
        },
        {
            **_groups()[1],
            "id": "g-b",
            "displayName": "B",
            "member_ids": ["g-a"],
        },
    ]
    _seed(source, groups=cycle)

    with pytest.raises(
        ScimMigrationError,
        match="cycles",
    ):
        migrate_scim_identity_store(
            source,
            target,
        )

    assert not target.database_path.exists()


def test_json_target_is_restored_byte_for_byte_on_write_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = _config(tmp_path / "source", "sqlite")
    target = _config(tmp_path / "target", "json")
    backups = tmp_path / "backups"
    _seed(source)
    _seed(
        target,
        users=[
            {
                **_users()[0],
                "id": "old-user",
                "userName": "old@example.test",
                "externalId": "old-subject",
            }
        ],
        groups=[],
    )
    original_users = target.user_path.read_bytes()
    original_groups = target.group_path.read_bytes()

    original_save_groups = ScimIdentityStore.save_groups

    def fail_target_groups(
        self: ScimIdentityStore,
        rows: list[dict],
    ) -> None:
        if (
            self.backend == "json"
            and self.group_path == target.group_path
        ):
            raise ScimStoreError("forced target group write failure")
        original_save_groups(self, rows)

    monkeypatch.setattr(
        ScimIdentityStore,
        "save_groups",
        fail_target_groups,
    )

    with pytest.raises(
        ScimMigrationError,
        match="write failed",
    ):
        migrate_scim_identity_store(
            source,
            target,
            replace=True,
            backup_dir=backups,
        )

    assert target.user_path.read_bytes() == original_users
    assert target.group_path.read_bytes() == original_groups
    assert len(list(backups.glob("scim-identity-*.json"))) == 1


def test_cli_dry_run_json_to_sqlite(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "source", "json")
    target = _config(tmp_path / "target", "sqlite")
    _seed(source)

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/scim_store_migrate.py",
            "--source-backend",
            "json",
            "--target-backend",
            "sqlite",
            "--source-user-path",
            str(source.user_path),
            "--source-group-path",
            str(source.group_path),
            "--target-database-path",
            str(target.database_path),
            "--dry-run",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["success"] is True
    assert payload["dry_run"] is True
    assert payload["users"] == 2
    assert payload["groups"] == 2
    assert not target.database_path.exists()


def test_cli_postgres_failure_does_not_expose_database_url(
    tmp_path: Path,
) -> None:
    secret = (
        "postgresql://secret-user:secret-password@"
        "127.0.0.1:1/breachscope"
    )
    env = dict(os.environ)
    env["TEST_SCIM_SOURCE_DATABASE_URL"] = secret

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/scim_store_migrate.py",
            "--source-backend",
            "postgres",
            "--target-backend",
            "json",
            "--source-database-url-env",
            "TEST_SCIM_SOURCE_DATABASE_URL",
            "--target-user-path",
            str(tmp_path / "users.json"),
            "--target-group-path",
            str(tmp_path / "groups.json"),
            "--dry-run",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert proc.returncode == 2
    assert "secret-password" not in proc.stderr
    assert secret not in proc.stderr
    payload = json.loads(proc.stderr)
    assert payload["success"] is False
    assert "PostgreSQL database cannot be opened" in payload["error"]



def test_packaged_module_cli_dry_run_json_to_sqlite(
    tmp_path: Path,
) -> None:
    source = _config(tmp_path / "source-module", "json")
    target = _config(tmp_path / "target-module", "sqlite")
    _seed(source)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "breachscope.scim_migrate",
            "--source-backend",
            "json",
            "--target-backend",
            "sqlite",
            "--source-user-path",
            str(source.user_path),
            "--source-group-path",
            str(source.group_path),
            "--target-database-path",
            str(target.database_path),
            "--dry-run",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["success"] is True
    assert payload["verified"] is False
    assert not target.database_path.exists()


def test_source_wrapper_help() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/scim_store_migrate.py",
            "--help",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0
    assert "--source-backend" in proc.stdout
    assert "--target-backend" in proc.stdout
