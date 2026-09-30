from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from api.services.scim_directory import (
    ScimDirectoryError,
    ScimUserDirectory,
)
from api.services.scim_groups import ScimGroupDirectory
from api.services.scim_store import (
    SCIM_POSTGRES_LOCK_ID,
    ScimIdentityStore,
    ScimStoreError,
    scim_database_url,
    scim_storage_backend,
)


class _Result:
    def __init__(self, rows=None):
        self._rows = list(rows or [])

    def fetchall(self):
        return list(self._rows)


class _FakePostgresConnection:
    def __init__(
        self,
        lock: threading.Lock,
        statements: list[tuple[str, object]],
    ):
        self.lock = lock
        self.statements = statements
        self.locked = False
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def execute(self, sql: str, params=None):
        normalized = " ".join(sql.split())
        self.statements.append((normalized, params))
        if "pg_advisory_xact_lock" in normalized:
            self.lock.acquire()
            self.locked = True
        return _Result()

    def executemany(self, sql: str, params):
        self.statements.append(
            (" ".join(sql.split()), list(params))
        )
        return _Result()

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def commit(self):
        self.commits += 1
        self._release()

    def rollback(self):
        self.rollbacks += 1
        self._release()

    def close(self):
        self.closed = True
        self._release()

    def _release(self):
        if self.locked:
            self.locked = False
            self.lock.release()


def _store() -> ScimIdentityStore:
    return ScimIdentityStore(
        backend="postgres",
        user_path=Path("unused-users.json"),
        group_path=Path("unused-groups.json"),
        database_path=Path("unused.db"),
        database_url="postgresql://db.example.test/breachscope",
    )


def test_postgres_backend_requires_database_url() -> None:
    assert scim_storage_backend(
        {"BS_SCIM_STORAGE_BACKEND": "postgres"}
    ) == "postgres"
    assert scim_database_url(
        {
            "BS_SCIM_DATABASE_URL": (
                "postgresql://db.example.test/breachscope"
            )
        }
    ) == "postgresql://db.example.test/breachscope"

    with pytest.raises(
        ScimDirectoryError,
        match="BS_SCIM_DATABASE_URL is required",
    ):
        ScimUserDirectory(
            backend="postgres",
            database_url="",
        )


def test_postgres_group_directory_reuses_user_transaction_store() -> None:
    users = ScimUserDirectory(
        backend="postgres",
        database_url="postgresql://db.example.test/breachscope",
    )
    groups = ScimGroupDirectory(
        user_directory=users,
    )
    assert groups.backend == "postgres"
    assert groups.store is users.store


def test_postgres_mutation_uses_one_advisory_transaction(
    monkeypatch,
) -> None:
    store = _store()
    lock = threading.Lock()
    statements: list[tuple[str, object]] = []
    connections: list[_FakePostgresConnection] = []

    def connect():
        conn = _FakePostgresConnection(lock, statements)
        connections.append(conn)
        return conn

    monkeypatch.setattr(store, "_postgres_connect", connect)

    with store.mutation():
        with store.mutation():
            assert store._active_connection() is connections[0]

    advisory = [
        row
        for row in statements
        if "pg_advisory_xact_lock" in row[0]
    ]
    assert len(connections) == 1
    assert len(advisory) == 1
    assert advisory[0][1] == (SCIM_POSTGRES_LOCK_ID,)
    assert connections[0].commits == 1
    assert connections[0].rollbacks == 0
    assert connections[0].closed is True


def test_postgres_save_users_uses_cursor_executemany(
    monkeypatch,
) -> None:
    store = _store()
    lock = threading.Lock()
    statements: list[tuple[str, object]] = []
    conn = _FakePostgresConnection(lock, statements)
    monkeypatch.setattr(store, "_postgres_connect", lambda: conn)

    store.save_users(
        [
            {
                "id": "u-1",
                "userName": "one@example.test",
                "externalId": "sub-u-1",
                "active": True,
                "role": "viewer",
                "organization_id": "org-one",
                "created": "2026-09-30T00:00:00Z",
                "last_modified": "2026-09-30T00:00:00Z",
            }
        ]
    )

    sql = [row[0] for row in statements]
    assert any("INSERT INTO scim_users" in statement for statement in sql)
    assert conn.commits == 1
    assert conn.rollbacks == 0
    assert conn.closed is True


def test_postgres_save_groups_and_members_use_cursor_executemany(
    monkeypatch,
) -> None:
    store = _store()
    lock = threading.Lock()
    statements: list[tuple[str, object]] = []
    conn = _FakePostgresConnection(lock, statements)
    monkeypatch.setattr(store, "_postgres_connect", lambda: conn)

    store.save_groups(
        [
            {
                "id": "g-1",
                "displayName": "Group One",
                "member_ids": ["u-1"],
                "role": "viewer",
                "organization_id": "org-one",
                "created": "2026-09-30T00:00:00Z",
                "last_modified": "2026-09-30T00:00:00Z",
            }
        ]
    )

    sql = [row[0] for row in statements]
    assert any("INSERT INTO scim_groups" in statement for statement in sql)
    assert any("INSERT INTO scim_group_members" in statement for statement in sql)
    assert conn.commits == 1
    assert conn.rollbacks == 0
    assert conn.closed is True


def test_postgres_mutation_rolls_back_on_error(
    monkeypatch,
) -> None:
    store = _store()
    lock = threading.Lock()
    statements: list[tuple[str, object]] = []
    conn = _FakePostgresConnection(lock, statements)
    monkeypatch.setattr(
        store,
        "_postgres_connect",
        lambda: conn,
    )

    with pytest.raises(RuntimeError, match="boom"):
        with store.mutation():
            raise RuntimeError("boom")

    assert conn.commits == 0
    assert conn.rollbacks == 1
    assert conn.closed is True


def test_two_postgres_replicas_serialize_mutation_critical_section(
    monkeypatch,
) -> None:
    database_lock = threading.Lock()
    statements: list[tuple[str, object]] = []
    stores = [_store(), _store()]

    for store in stores:
        monkeypatch.setattr(
            store,
            "_postgres_connect",
            lambda lock=database_lock: _FakePostgresConnection(
                lock,
                statements,
            ),
        )

    shared = {"value": 0}
    errors: list[Exception] = []
    start = threading.Barrier(2)

    def worker(store: ScimIdentityStore) -> None:
        try:
            start.wait(timeout=2)
            with store.mutation():
                current = shared["value"]
                time.sleep(0.05)
                shared["value"] = current + 1
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(store,))
        for store in stores
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)

    assert errors == []
    assert shared["value"] == 2
    assert all(not thread.is_alive() for thread in threads)
    advisory_calls = [
        row
        for row in statements
        if "pg_advisory_xact_lock" in row[0]
    ]
    assert len(advisory_calls) == 2



def test_postgres_snapshot_uses_repeatable_read_without_write_lock(
    monkeypatch,
) -> None:
    store = _store()
    lock = threading.Lock()
    statements: list[tuple[str, object]] = []
    conn = _FakePostgresConnection(lock, statements)
    monkeypatch.setattr(
        store,
        "_postgres_connect",
        lambda: conn,
    )

    with store.snapshot():
        with store.snapshot():
            assert store._active_connection() is conn

    sql = [row[0] for row in statements]
    assert (
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
        in sql
    )
    assert not any(
        "pg_advisory_xact_lock" in statement
        for statement in sql
    )
    assert conn.commits == 1
    assert conn.rollbacks == 0
    assert conn.closed is True


def test_postgres_mutation_inside_snapshot_fails_closed(
    monkeypatch,
) -> None:
    store = _store()
    lock = threading.Lock()
    statements: list[tuple[str, object]] = []
    conn = _FakePostgresConnection(lock, statements)
    monkeypatch.setattr(
        store,
        "_postgres_connect",
        lambda: conn,
    )

    with pytest.raises(
        ScimStoreError,
        match="cannot run inside a read-only snapshot",
    ):
        with store.snapshot():
            with store.mutation():
                pass

    assert conn.rollbacks == 1
    assert conn.closed is True
