"""Storage backends for SCIM identity state."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any, Mapping


SCIM_STORAGE_BACKENDS = {"json", "sqlite"}


class ScimStoreError(RuntimeError):
    """Raised when SCIM identity storage cannot be read or written."""


def scim_storage_backend(
    env: Mapping[str, str] | None = None,
) -> str:
    source = os.environ if env is None else env
    value = str(
        source.get("BS_SCIM_STORAGE_BACKEND", "") or "json"
    ).strip().casefold()
    if value not in SCIM_STORAGE_BACKENDS:
        raise ScimStoreError(
            "BS_SCIM_STORAGE_BACKEND must be json or sqlite."
        )
    return value


def scim_database_path(
    env: Mapping[str, str] | None = None,
) -> Path:
    source = os.environ if env is None else env
    value = str(
        source.get("BS_SCIM_DATABASE_PATH", "") or ""
    ).strip()
    if not value:
        value = "~/.breachscope/scim_identity.db"
    return Path(value).expanduser()


class ScimIdentityStore:
    """Persist SCIM users/groups in JSON files or one SQLite database."""

    def __init__(
        self,
        *,
        backend: str,
        user_path: Path,
        group_path: Path,
        database_path: Path,
    ):
        normalized = str(backend or "").strip().casefold()
        if normalized not in SCIM_STORAGE_BACKENDS:
            raise ScimStoreError(
                "SCIM storage backend must be json or sqlite."
            )
        self.backend = normalized
        self.user_path = Path(user_path)
        self.group_path = Path(group_path)
        self.database_path = Path(database_path)

    def load_users(self) -> list[dict[str, Any]]:
        if self.backend == "json":
            return self._load_json_rows(
                self.user_path,
                collection="users",
                required_fields=("id", "userName"),
            )
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    """
                    SELECT
                        id,
                        user_name,
                        external_id,
                        active,
                        role,
                        organization_id,
                        created,
                        last_modified
                    FROM scim_users
                    ORDER BY rowid
                    """
                ).fetchall()
        except sqlite3.Error as exc:
            raise ScimStoreError(
                "SCIM SQLite user store is unreadable."
            ) from exc
        return [
            {
                "id": str(row["id"]),
                "userName": str(row["user_name"]),
                "externalId": str(row["external_id"] or ""),
                "active": bool(row["active"]),
                "role": str(row["role"] or ""),
                "organization_id": str(
                    row["organization_id"] or ""
                ),
                "created": str(row["created"] or ""),
                "last_modified": str(
                    row["last_modified"] or ""
                ),
            }
            for row in rows
        ]

    def save_users(
        self,
        rows: list[dict[str, Any]],
    ) -> None:
        if self.backend == "json":
            self._save_json_rows(
                self.user_path,
                collection="users",
                rows=rows,
            )
            return

        try:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM scim_users")
                conn.executemany(
                    """
                    INSERT INTO scim_users (
                        id,
                        user_name,
                        external_id,
                        active,
                        role,
                        organization_id,
                        created,
                        last_modified
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            str(row.get("id") or ""),
                            str(row.get("userName") or ""),
                            str(row.get("externalId") or ""),
                            1 if bool(row.get("active", False)) else 0,
                            str(row.get("role") or ""),
                            str(row.get("organization_id") or ""),
                            str(row.get("created") or ""),
                            str(row.get("last_modified") or ""),
                        )
                        for row in rows
                    ],
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ScimStoreError(
                "SCIM SQLite user store violates a uniqueness constraint."
            ) from exc
        except sqlite3.Error as exc:
            raise ScimStoreError(
                "SCIM SQLite user store is not writable."
            ) from exc

    def load_groups(self) -> list[dict[str, Any]]:
        if self.backend == "json":
            return self._load_json_rows(
                self.group_path,
                collection="groups",
                required_fields=("id", "displayName"),
            )
        try:
            with closing(self._connect()) as conn:
                groups = conn.execute(
                    """
                    SELECT
                        id,
                        display_name,
                        role,
                        organization_id,
                        created,
                        last_modified
                    FROM scim_groups
                    ORDER BY rowid
                    """
                ).fetchall()
                members = conn.execute(
                    """
                    SELECT group_id, member_id, ordinal
                    FROM scim_group_members
                    ORDER BY group_id, ordinal
                    """
                ).fetchall()
        except sqlite3.Error as exc:
            raise ScimStoreError(
                "SCIM SQLite group store is unreadable."
            ) from exc

        members_by_group: dict[str, list[str]] = {}
        for member in members:
            members_by_group.setdefault(
                str(member["group_id"]),
                [],
            ).append(str(member["member_id"]))

        return [
            {
                "id": str(row["id"]),
                "displayName": str(row["display_name"]),
                "member_ids": members_by_group.get(
                    str(row["id"]),
                    [],
                ),
                "role": str(row["role"] or ""),
                "organization_id": str(
                    row["organization_id"] or ""
                ),
                "created": str(row["created"] or ""),
                "last_modified": str(
                    row["last_modified"] or ""
                ),
            }
            for row in groups
        ]

    def save_groups(
        self,
        rows: list[dict[str, Any]],
    ) -> None:
        if self.backend == "json":
            self._save_json_rows(
                self.group_path,
                collection="groups",
                rows=rows,
            )
            return

        try:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM scim_group_members")
                conn.execute("DELETE FROM scim_groups")
                conn.executemany(
                    """
                    INSERT INTO scim_groups (
                        id,
                        display_name,
                        role,
                        organization_id,
                        created,
                        last_modified
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            str(row.get("id") or ""),
                            str(row.get("displayName") or ""),
                            str(row.get("role") or ""),
                            str(row.get("organization_id") or ""),
                            str(row.get("created") or ""),
                            str(row.get("last_modified") or ""),
                        )
                        for row in rows
                    ],
                )
                member_rows: list[tuple[str, str, int]] = []
                for row in rows:
                    group_id = str(row.get("id") or "")
                    for ordinal, raw_member_id in enumerate(
                        row.get("member_ids") or []
                    ):
                        member_rows.append(
                            (
                                group_id,
                                str(raw_member_id),
                                ordinal,
                            )
                        )
                if member_rows:
                    conn.executemany(
                        """
                        INSERT INTO scim_group_members (
                            group_id,
                            member_id,
                            ordinal
                        )
                        VALUES (?, ?, ?)
                        """,
                        member_rows,
                    )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ScimStoreError(
                "SCIM SQLite group store violates a uniqueness constraint."
            ) from exc
        except sqlite3.Error as exc:
            raise ScimStoreError(
                "SCIM SQLite group store is not writable."
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        try:
            self.database_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            conn = sqlite3.connect(
                self.database_path,
                timeout=5.0,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            self._ensure_schema(conn)
            return conn
        except (OSError, sqlite3.Error) as exc:
            raise ScimStoreError(
                "SCIM SQLite database cannot be opened."
            ) from exc

    @staticmethod
    def _ensure_schema(
        conn: sqlite3.Connection,
    ) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scim_users (
                id TEXT PRIMARY KEY,
                user_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                external_id TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT '',
                organization_id TEXT NOT NULL DEFAULT '',
                created TEXT NOT NULL,
                last_modified TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS
                scim_users_external_id_unique
            ON scim_users(external_id)
            WHERE external_id <> '';

            CREATE TABLE IF NOT EXISTS scim_groups (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                role TEXT NOT NULL DEFAULT '',
                organization_id TEXT NOT NULL DEFAULT '',
                created TEXT NOT NULL,
                last_modified TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scim_group_members (
                group_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                PRIMARY KEY (group_id, member_id),
                FOREIGN KEY (group_id)
                    REFERENCES scim_groups(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS
                scim_group_members_member_idx
            ON scim_group_members(member_id);
            """
        )

    @staticmethod
    def _load_json_rows(
        path: Path,
        *,
        collection: str,
        required_fields: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            payload = json.loads(
                path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise ScimStoreError(
                f"SCIM {collection} JSON store is unreadable or invalid."
            ) from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get(collection),
            list,
        ):
            raise ScimStoreError(
                f"SCIM {collection} JSON store format is invalid."
            )

        result: list[dict[str, Any]] = []
        for row in payload[collection]:
            if not isinstance(row, dict):
                continue
            if not all(row.get(field) for field in required_fields):
                continue
            result.append(dict(row))
        return result

    @staticmethod
    def _save_json_rows(
        path: Path,
        *,
        collection: str,
        rows: list[dict[str, Any]],
    ) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema_version": 1,
                collection: rows,
            }
            temp = path.with_name(
                path.name + f".{uuid.uuid4().hex}.tmp"
            )
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
        except OSError as exc:
            raise ScimStoreError(
                f"SCIM {collection} JSON store is not writable."
            ) from exc
