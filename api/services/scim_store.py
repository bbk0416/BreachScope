"""Storage backends for SCIM identity state."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - guarded at runtime
    psycopg = None
    dict_row = None


SCIM_STORAGE_BACKENDS = {"json", "sqlite", "postgres"}
SCIM_POSTGRES_LOCK_ID = 0x425343494D


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
            "BS_SCIM_STORAGE_BACKEND must be json, sqlite, or postgres."
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


def scim_database_url(
    env: Mapping[str, str] | None = None,
) -> str:
    source = os.environ if env is None else env
    return str(
        source.get("BS_SCIM_DATABASE_URL", "") or ""
    ).strip()


class ScimIdentityStore:
    """Persist SCIM identity state in JSON, SQLite, or PostgreSQL."""

    def __init__(
        self,
        *,
        backend: str,
        user_path: Path,
        group_path: Path,
        database_path: Path,
        database_url: str = "",
    ):
        normalized = str(backend or "").strip().casefold()
        if normalized not in SCIM_STORAGE_BACKENDS:
            raise ScimStoreError(
                "SCIM storage backend must be json, sqlite, or postgres."
            )
        if normalized == "postgres" and not str(database_url or "").strip():
            raise ScimStoreError(
                "BS_SCIM_DATABASE_URL is required for postgres SCIM storage."
            )
        self.backend = normalized
        self.user_path = Path(user_path)
        self.group_path = Path(group_path)
        self.database_path = Path(database_path)
        self.database_url = str(database_url or "").strip()
        self._transaction = threading.local()

    @contextmanager
    def snapshot(self) -> Iterator[None]:
        """Read one consistent identity snapshot across related tables."""
        if self.backend == "json":
            yield
            return

        current = getattr(self._transaction, "connection", None)
        if current is not None:
            self._transaction.depth = (
                int(getattr(self._transaction, "depth", 1)) + 1
            )
            try:
                yield
            finally:
                self._transaction.depth -= 1
            return

        conn = (
            self._sqlite_connect()
            if self.backend == "sqlite"
            else self._postgres_connect()
        )
        try:
            if self.backend == "sqlite":
                conn.execute("BEGIN")
            else:
                conn.execute(
                    "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
                )
            self._transaction.connection = conn
            self._transaction.depth = 1
            self._transaction.mode = "snapshot"
            yield
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            self._transaction.connection = None
            self._transaction.depth = 0
            self._transaction.mode = None
            conn.close()

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Serialize one read/validate/write mutation for DB backends."""
        if self.backend == "json":
            yield
            return

        current = getattr(self._transaction, "connection", None)
        if current is not None:
            if getattr(self._transaction, "mode", None) == "snapshot":
                raise ScimStoreError(
                    "SCIM mutation cannot run inside a read-only snapshot."
                )
            self._transaction.depth = (
                int(getattr(self._transaction, "depth", 1)) + 1
            )
            try:
                yield
            finally:
                self._transaction.depth -= 1
            return

        conn = (
            self._sqlite_connect()
            if self.backend == "sqlite"
            else self._postgres_connect()
        )
        try:
            if self.backend == "sqlite":
                conn.execute("BEGIN IMMEDIATE")
            else:
                conn.execute("BEGIN")
                conn.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (SCIM_POSTGRES_LOCK_ID,),
                )
            self._transaction.connection = conn
            self._transaction.depth = 1
            self._transaction.mode = "mutation"
            yield
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            self._transaction.connection = None
            self._transaction.depth = 0
            self._transaction.mode = None
            conn.close()

    def load_users(self) -> list[dict[str, Any]]:
        if self.backend == "json":
            return self._load_json_rows(
                self.user_path,
                collection="users",
                required_fields=("id", "userName"),
            )
        if self.backend == "sqlite":
            return self._load_sqlite_users()
        return self._load_postgres_users()

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
        if self.backend == "sqlite":
            self._save_sqlite_users(rows)
            return
        self._save_postgres_users(rows)

    def load_groups(self) -> list[dict[str, Any]]:
        if self.backend == "json":
            return self._load_json_rows(
                self.group_path,
                collection="groups",
                required_fields=("id", "displayName"),
            )
        if self.backend == "sqlite":
            return self._load_sqlite_groups()
        return self._load_postgres_groups()

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
        if self.backend == "sqlite":
            self._save_sqlite_groups(rows)
            return
        self._save_postgres_groups(rows)

    def _active_connection(self) -> Any | None:
        return getattr(self._transaction, "connection", None)

    def _load_sqlite_users(self) -> list[dict[str, Any]]:
        active = self._active_connection()
        conn = active or self._sqlite_connect()
        try:
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
        finally:
            if active is None:
                conn.close()
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
                "last_modified": str(row["last_modified"] or ""),
            }
            for row in rows
        ]

    def _save_sqlite_users(
        self,
        rows: list[dict[str, Any]],
    ) -> None:
        active = self._active_connection()
        conn = active or self._sqlite_connect()
        try:
            if active is None:
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
            if active is None:
                conn.commit()
        except sqlite3.IntegrityError as exc:
            if active is None:
                conn.rollback()
            raise ScimStoreError(
                "SCIM SQLite user store violates a uniqueness constraint."
            ) from exc
        except sqlite3.Error as exc:
            if active is None:
                conn.rollback()
            raise ScimStoreError(
                "SCIM SQLite user store is not writable."
            ) from exc
        finally:
            if active is None:
                conn.close()

    def _load_sqlite_groups(self) -> list[dict[str, Any]]:
        active = self._active_connection()
        conn = active or self._sqlite_connect()
        try:
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
        finally:
            if active is None:
                conn.close()
        return self._group_rows(groups, members)

    def _save_sqlite_groups(
        self,
        rows: list[dict[str, Any]],
    ) -> None:
        active = self._active_connection()
        conn = active or self._sqlite_connect()
        try:
            if active is None:
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
            member_rows = self._member_rows(rows)
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
            if active is None:
                conn.commit()
        except sqlite3.IntegrityError as exc:
            if active is None:
                conn.rollback()
            raise ScimStoreError(
                "SCIM SQLite group store violates a uniqueness constraint."
            ) from exc
        except sqlite3.Error as exc:
            if active is None:
                conn.rollback()
            raise ScimStoreError(
                "SCIM SQLite group store is not writable."
            ) from exc
        finally:
            if active is None:
                conn.close()

    def _load_postgres_users(self) -> list[dict[str, Any]]:
        active = self._active_connection()
        conn = active or self._postgres_connect()
        try:
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
                ORDER BY created, id
                """
            ).fetchall()
        except Exception as exc:
            raise ScimStoreError(
                "SCIM PostgreSQL user store is unreadable."
            ) from exc
        finally:
            if active is None:
                conn.close()
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
                "last_modified": str(row["last_modified"] or ""),
            }
            for row in rows
        ]

    def _save_postgres_users(
        self,
        rows: list[dict[str, Any]],
    ) -> None:
        active = self._active_connection()
        conn = active or self._postgres_connect()
        try:
            if active is None:
                conn.execute("BEGIN")
                conn.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (SCIM_POSTGRES_LOCK_ID,),
                )
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
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [
                    (
                        str(row.get("id") or ""),
                        str(row.get("userName") or ""),
                        str(row.get("externalId") or ""),
                        bool(row.get("active", False)),
                        str(row.get("role") or ""),
                        str(row.get("organization_id") or ""),
                        str(row.get("created") or ""),
                        str(row.get("last_modified") or ""),
                    )
                    for row in rows
                ],
            )
            if active is None:
                conn.commit()
        except Exception as exc:
            if active is None:
                conn.rollback()
            raise ScimStoreError(
                "SCIM PostgreSQL user store is not writable."
            ) from exc
        finally:
            if active is None:
                conn.close()

    def _load_postgres_groups(self) -> list[dict[str, Any]]:
        active = self._active_connection()
        conn = active or self._postgres_connect()
        try:
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
                ORDER BY created, id
                """
            ).fetchall()
            members = conn.execute(
                """
                SELECT group_id, member_id, ordinal
                FROM scim_group_members
                ORDER BY group_id, ordinal
                """
            ).fetchall()
        except Exception as exc:
            raise ScimStoreError(
                "SCIM PostgreSQL group store is unreadable."
            ) from exc
        finally:
            if active is None:
                conn.close()
        return self._group_rows(groups, members)

    def _save_postgres_groups(
        self,
        rows: list[dict[str, Any]],
    ) -> None:
        active = self._active_connection()
        conn = active or self._postgres_connect()
        try:
            if active is None:
                conn.execute("BEGIN")
                conn.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (SCIM_POSTGRES_LOCK_ID,),
                )
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
                VALUES (%s, %s, %s, %s, %s, %s)
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
            member_rows = self._member_rows(rows)
            if member_rows:
                conn.executemany(
                    """
                    INSERT INTO scim_group_members (
                        group_id,
                        member_id,
                        ordinal
                    )
                    VALUES (%s, %s, %s)
                    """,
                    member_rows,
                )
            if active is None:
                conn.commit()
        except Exception as exc:
            if active is None:
                conn.rollback()
            raise ScimStoreError(
                "SCIM PostgreSQL group store is not writable."
            ) from exc
        finally:
            if active is None:
                conn.close()

    def _sqlite_connect(self) -> sqlite3.Connection:
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
            self._ensure_sqlite_schema(conn)
            return conn
        except (OSError, sqlite3.Error) as exc:
            raise ScimStoreError(
                "SCIM SQLite database cannot be opened."
            ) from exc

    def _postgres_connect(self) -> Any:
        if psycopg is None or dict_row is None:
            raise ScimStoreError(
                "PostgreSQL SCIM storage requires the psycopg driver."
            )
        try:
            conn = psycopg.connect(
                self.database_url,
                connect_timeout=5,
                row_factory=dict_row,
            )
            self._ensure_postgres_schema(conn)
            conn.commit()
            return conn
        except Exception as exc:
            raise ScimStoreError(
                "SCIM PostgreSQL database cannot be opened."
            ) from exc

    @staticmethod
    def _ensure_sqlite_schema(
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
    def _ensure_postgres_schema(conn: Any) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scim_users (
                id TEXT PRIMARY KEY,
                user_name TEXT NOT NULL,
                external_id TEXT NOT NULL DEFAULT '',
                active BOOLEAN NOT NULL,
                role TEXT NOT NULL DEFAULT '',
                organization_id TEXT NOT NULL DEFAULT '',
                created TEXT NOT NULL,
                last_modified TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
                scim_users_user_name_unique
            ON scim_users (LOWER(user_name))
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
                scim_users_external_id_unique
            ON scim_users (external_id)
            WHERE external_id <> ''
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scim_groups (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT '',
                organization_id TEXT NOT NULL DEFAULT '',
                created TEXT NOT NULL,
                last_modified TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
                scim_groups_display_name_unique
            ON scim_groups (LOWER(display_name))
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scim_group_members (
                group_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                PRIMARY KEY (group_id, member_id),
                FOREIGN KEY (group_id)
                    REFERENCES scim_groups(id)
                    ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS
                scim_group_members_member_idx
            ON scim_group_members(member_id)
            """
        )

    @staticmethod
    def _group_rows(
        groups: Any,
        members: Any,
    ) -> list[dict[str, Any]]:
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
                "last_modified": str(row["last_modified"] or ""),
            }
            for row in groups
        ]

    @staticmethod
    def _member_rows(
        rows: list[dict[str, Any]],
    ) -> list[tuple[str, str, int]]:
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
        return member_rows

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
