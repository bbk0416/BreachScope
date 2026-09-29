"""Safe migration helpers for BreachScope SCIM identity stores."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from api.services.organization_scope import normalize_organization_id
from api.services.scim_directory import KNOWN_ROLES
from api.services.scim_groups import _validate_group_graph
from api.services.scim_store import (
    SCIM_STORAGE_BACKENDS,
    ScimIdentityStore,
    ScimStoreError,
    dict_row,
    psycopg,
)


class ScimMigrationError(RuntimeError):
    """Raised when a SCIM identity-store migration cannot proceed."""


@dataclass(frozen=True)
class ScimStoreConfig:
    backend: str
    user_path: Path
    group_path: Path
    database_path: Path
    database_url: str = ""

    def normalized_backend(self) -> str:
        value = str(self.backend or "").strip().casefold()
        if value not in SCIM_STORAGE_BACKENDS:
            raise ScimMigrationError(
                "SCIM migration backend must be json, sqlite, or postgres."
            )
        if value == "postgres" and not str(
            self.database_url or ""
        ).strip():
            raise ScimMigrationError(
                "PostgreSQL migration storage requires a database URL."
            )
        return value

    def location_label(self) -> str:
        backend = self.normalized_backend()
        if backend == "json":
            return (
                f"users={self.user_path};groups={self.group_path}"
            )
        if backend == "sqlite":
            return str(self.database_path)
        return "configured PostgreSQL database"

    def identity_key(self) -> tuple[str, ...]:
        backend = self.normalized_backend()
        if backend == "json":
            return (
                backend,
                str(self.user_path.resolve()),
                str(self.group_path.resolve()),
            )
        if backend == "sqlite":
            return (
                backend,
                str(self.database_path.resolve()),
            )
        return (
            backend,
            str(self.database_url),
        )

    def build(self) -> ScimIdentityStore:
        return ScimIdentityStore(
            backend=self.normalized_backend(),
            user_path=self.user_path,
            group_path=self.group_path,
            database_path=self.database_path,
            database_url=self.database_url,
        )


def _canonical_rows(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        [dict(row) for row in rows],
        key=lambda row: str(row.get("id") or ""),
    )


def _snapshot_digest(
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> str:
    payload = {
        "users": _canonical_rows(users),
        "groups": _canonical_rows(groups),
    }
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _assignment_is_valid(
    row: Mapping[str, Any],
    *,
    label: str,
) -> None:
    role = str(row.get("role") or "").strip().casefold()
    organization_id = str(
        row.get("organization_id") or ""
    ).strip()
    if role and role not in KNOWN_ROLES:
        raise ScimMigrationError(
            f"{label} contains unsupported role: {role}"
        )
    if bool(role) != bool(organization_id):
        raise ScimMigrationError(
            f"{label} assignment requires both role and organization_id."
        )
    if organization_id:
        try:
            normalize_organization_id(
                organization_id,
                default=None,
            )
        except ValueError as exc:
            raise ScimMigrationError(
                f"{label} contains invalid organization_id."
            ) from exc


def validate_identity_snapshot(
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> None:
    user_ids: set[str] = set()
    user_names: set[str] = set()
    external_ids: set[str] = set()

    for row in users:
        user_id = str(row.get("id") or "").strip()
        user_name = str(row.get("userName") or "").strip()
        external_id = str(row.get("externalId") or "").strip()
        if not user_id or not user_name:
            raise ScimMigrationError(
                "SCIM source contains a User without id or userName."
            )
        if user_id in user_ids:
            raise ScimMigrationError(
                f"SCIM source contains duplicate User id: {user_id}"
            )
        folded = user_name.casefold()
        if folded in user_names:
            raise ScimMigrationError(
                "SCIM source contains duplicate case-insensitive userName."
            )
        if external_id and external_id in external_ids:
            raise ScimMigrationError(
                "SCIM source contains duplicate externalId."
            )
        if bool(row.get("active", False)) and not external_id:
            raise ScimMigrationError(
                "Active SCIM source User is missing externalId."
            )
        _assignment_is_valid(
            row,
            label=f"SCIM User {user_id}",
        )
        user_ids.add(user_id)
        user_names.add(folded)
        if external_id:
            external_ids.add(external_id)

    group_ids: set[str] = set()
    group_names: set[str] = set()
    for row in groups:
        group_id = str(row.get("id") or "").strip()
        display_name = str(
            row.get("displayName") or ""
        ).strip()
        if not group_id or not display_name:
            raise ScimMigrationError(
                "SCIM source contains a Group without id or displayName."
            )
        if group_id in group_ids:
            raise ScimMigrationError(
                f"SCIM source contains duplicate Group id: {group_id}"
            )
        folded = display_name.casefold()
        if folded in group_names:
            raise ScimMigrationError(
                "SCIM source contains duplicate case-insensitive displayName."
            )
        _assignment_is_valid(
            row,
            label=f"SCIM Group {group_id}",
        )
        group_ids.add(group_id)
        group_names.add(folded)

    try:
        _validate_group_graph(
            groups,
            valid_user_ids=user_ids,
        )
    except Exception as exc:
        raise ScimMigrationError(str(exc)) from exc


def _read_existing_config_snapshot(
    config: ScimStoreConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    backend = config.normalized_backend()
    store = config.build()

    if backend == "json":
        return read_identity_snapshot(store)

    if backend == "sqlite":
        if not config.database_path.exists():
            return [], []
        uri = config.database_path.resolve().as_uri() + "?mode=ro"
        try:
            conn = sqlite3.connect(
                uri,
                uri=True,
                timeout=5.0,
            )
            conn.row_factory = sqlite3.Row
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name IN "
                    "('scim_users','scim_groups','scim_group_members')"
                ).fetchall()
            }
            if not tables:
                conn.close()
                return [], []
            required = {
                "scim_users",
                "scim_groups",
                "scim_group_members",
            }
            if not required.issubset(tables):
                conn.close()
                raise ScimMigrationError(
                    "SQLite target/source has an incomplete SCIM schema."
                )
            store._transaction.connection = conn
            store._transaction.depth = 1
            store._transaction.mode = "snapshot"
            try:
                users = store.load_users()
                groups = store.load_groups()
            finally:
                store._transaction.connection = None
                store._transaction.depth = 0
                store._transaction.mode = None
                conn.close()
        except ScimMigrationError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ScimMigrationError(
                "SCIM SQLite database cannot be read without modification."
            ) from exc
        validate_identity_snapshot(users, groups)
        return users, groups

    if psycopg is None or dict_row is None:
        raise ScimMigrationError(
            "PostgreSQL SCIM migration requires the psycopg driver."
        )
    try:
        conn = psycopg.connect(
            config.database_url,
            connect_timeout=5,
            row_factory=dict_row,
        )
        conn.execute(
            "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
        )
        row = conn.execute(
            "SELECT "
            "to_regclass('public.scim_users') AS users, "
            "to_regclass('public.scim_groups') AS groups, "
            "to_regclass('public.scim_group_members') AS members"
        ).fetchone()
        values = {
            str(row["users"] or ""),
            str(row["groups"] or ""),
            str(row["members"] or ""),
        }
        values.discard("")
        if not values:
            conn.rollback()
            conn.close()
            return [], []
        if len(values) != 3:
            conn.rollback()
            conn.close()
            raise ScimMigrationError(
                "PostgreSQL target/source has an incomplete SCIM schema."
            )
        store._transaction.connection = conn
        store._transaction.depth = 1
        store._transaction.mode = "snapshot"
        try:
            users = store.load_users()
            groups = store.load_groups()
        finally:
            store._transaction.connection = None
            store._transaction.depth = 0
            store._transaction.mode = None
            conn.rollback()
            conn.close()
    except ScimMigrationError:
        raise
    except Exception as exc:
        raise ScimMigrationError(
            "SCIM PostgreSQL database cannot be opened or read."
        ) from exc
    validate_identity_snapshot(users, groups)
    return users, groups


def read_identity_snapshot(
    store: ScimIdentityStore,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        with store.snapshot():
            users = store.load_users()
            groups = store.load_groups()
    except ScimStoreError as exc:
        raise ScimMigrationError(str(exc)) from exc
    validate_identity_snapshot(users, groups)
    return users, groups


def write_snapshot_backup(
    backup_dir: Path,
    *,
    backend: str,
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).isoformat()
    stamp = (
        created_at.replace("-", "")
        .replace(":", "")
        .replace("+00:00", "Z")
        .replace(".", "")
    )
    path = backup_dir / (
        f"scim-identity-{stamp}-{uuid.uuid4().hex[:8]}.json"
    )
    payload = {
        "schema_version": 1,
        "created_at": created_at,
        "backend": str(backend),
        "users": users,
        "groups": groups,
        "sha256": _snapshot_digest(users, groups),
    }
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temp, path)
    return path




def _capture_json_target(
    config: ScimStoreConfig,
) -> dict[Path, bytes | None]:
    return {
        config.user_path: (
            config.user_path.read_bytes()
            if config.user_path.exists()
            else None
        ),
        config.group_path: (
            config.group_path.read_bytes()
            if config.group_path.exists()
            else None
        ),
    }


def _restore_json_target(
    snapshot: Mapping[Path, bytes | None],
) -> None:
    for path, content in snapshot.items():
        if content is None:
            path.unlink(missing_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(
            path.name + f".{uuid.uuid4().hex}.restore.tmp"
        )
        temp.write_bytes(content)
        os.replace(temp, path)


def _restore_identity_target(
    store: ScimIdentityStore,
    *,
    backend: str,
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    json_snapshot: Mapping[Path, bytes | None] | None,
) -> None:
    if backend == "json":
        assert json_snapshot is not None
        _restore_json_target(json_snapshot)
        return
    with store.mutation():
        store.save_users(users)
        store.save_groups(groups)


def migrate_scim_identity_store(
    source: ScimStoreConfig,
    target: ScimStoreConfig,
    *,
    replace: bool = False,
    dry_run: bool = False,
    backup_dir: Path | None = None,
) -> dict[str, Any]:
    source_backend = source.normalized_backend()
    target_backend = target.normalized_backend()
    if source.identity_key() == target.identity_key():
        raise ScimMigrationError(
            "Source and target SCIM identity stores are the same."
        )

    users, groups = _read_existing_config_snapshot(source)
    source_digest = _snapshot_digest(users, groups)

    existing_users, existing_groups = (
        _read_existing_config_snapshot(target)
    )

    target_nonempty = bool(existing_users or existing_groups)
    if target_nonempty and not replace:
        raise ScimMigrationError(
            "Target SCIM identity store is not empty; use --replace to overwrite it."
        )

    result: dict[str, Any] = {
        "success": True,
        "dry_run": bool(dry_run),
        "source_backend": source_backend,
        "target_backend": target_backend,
        "source_location": source.location_label(),
        "target_location": target.location_label(),
        "users": len(users),
        "groups": len(groups),
        "target_existing_users": len(existing_users),
        "target_existing_groups": len(existing_groups),
        "source_sha256": source_digest,
        "backup_path": None,
        "verified": False,
    }
    if dry_run:
        return result

    target_store = target.build()

    backup_path: Path | None = None
    if target_nonempty:
        backup_root = (
            backup_dir.expanduser()
            if backup_dir is not None
            else Path("~/.breachscope/scim-migration-backups").expanduser()
        )
        backup_path = write_snapshot_backup(
            backup_root,
            backend=target_backend,
            users=existing_users,
            groups=existing_groups,
        )
        result["backup_path"] = str(backup_path)

    json_snapshot = (
        _capture_json_target(target)
        if target_backend == "json"
        else None
    )

    try:
        with target_store.mutation():
            target_store.save_users(users)
            target_store.save_groups(groups)

        migrated_users, migrated_groups = read_identity_snapshot(
            target_store
        )
        target_digest = _snapshot_digest(
            migrated_users,
            migrated_groups,
        )
        if target_digest != source_digest:
            raise ScimMigrationError(
                "SCIM migration verification failed: target snapshot differs from source."
            )
    except Exception as exc:
        try:
            _restore_identity_target(
                target_store,
                backend=target_backend,
                users=existing_users,
                groups=existing_groups,
                json_snapshot=json_snapshot,
            )
        except Exception as rollback_exc:
            raise ScimMigrationError(
                "SCIM migration failed and target rollback also failed. "
                f"Backup: {backup_path or 'not-created'}"
            ) from rollback_exc
        if isinstance(exc, ScimMigrationError):
            raise
        raise ScimMigrationError(
            f"SCIM migration write failed: {exc}"
        ) from exc

    result["target_sha256"] = target_digest
    result["verified"] = True
    return result
