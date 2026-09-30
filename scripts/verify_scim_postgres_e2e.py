#!/usr/bin/env python3
"""Run BreachScope SCIM storage against an isolated real PostgreSQL cluster."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api.services.scim_migration import (  # noqa: E402
    ScimStoreConfig,
    migrate_scim_identity_store,
)
from api.services.scim_store import ScimIdentityStore  # noqa: E402

ADMIN = "breachscope_e2e_admin"
DBNAME = "breachscope_e2e"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _pg_bin(explicit: str) -> Path:
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if (candidate / "initdb.exe").exists() or (candidate / "initdb").exists():
            return candidate
        raise RuntimeError(f"PostgreSQL bin directory is invalid: {candidate}")

    initdb = shutil.which("initdb")
    pg_ctl = shutil.which("pg_ctl")
    if initdb and pg_ctl and Path(initdb).parent == Path(pg_ctl).parent:
        return Path(initdb).parent

    if os.name == "nt":
        base = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "PostgreSQL"
        candidates = []
        if base.exists():
            for child in base.iterdir():
                bin_dir = child / "bin"
                if (bin_dir / "initdb.exe").exists() and (bin_dir / "pg_ctl.exe").exists():
                    try:
                        version_key = tuple(int(x) for x in child.name.split("."))
                    except ValueError:
                        version_key = (0,)
                    candidates.append((version_key, bin_dir))
        if candidates:
            return max(candidates, key=lambda item: item[0])[1]

    raise RuntimeError(
        "PostgreSQL initdb/pg_ctl not found. Use --pg-bin or install PostgreSQL."
    )


def _exe(pg_bin: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    path = pg_bin / f"{name}{suffix}"
    if not path.exists():
        raise RuntimeError(f"Required PostgreSQL executable is missing: {path}")
    return path


def _grant_windows_temp_acl(path: Path) -> None:
    if os.name != "nt":
        return
    domain = str(os.environ.get("USERDOMAIN") or "").strip()
    username = str(os.environ.get("USERNAME") or "").strip()
    account = f"{domain}\\{username}" if domain and username else username
    if not account:
        raise RuntimeError("Cannot determine the Windows account for temp ACL setup.")
    subprocess.run(
        ["icacls", str(path), "/grant", f"{account}:(OI)(CI)F"],
        check=True,
        capture_output=True,
        text=True,
    )


def _store(url: str) -> ScimIdentityStore:
    return ScimIdentityStore(
        backend="postgres",
        user_path=Path("unused-users.json"),
        group_path=Path("unused-groups.json"),
        database_path=Path("unused.db"),
        database_url=url,
    )


def _user(uid: str, name: str) -> dict:
    return {
        "id": uid,
        "userName": name,
        "externalId": f"sub-{uid}",
        "active": True,
        "role": "reviewer",
        "organization_id": "e2e-org",
        "created": "2026-09-30T00:00:00Z",
        "last_modified": "2026-09-30T00:00:00Z",
    }


def _group(gid: str, name: str, members: list[str]) -> dict:
    return {
        "id": gid,
        "displayName": name,
        "member_ids": list(members),
        "role": "reviewer",
        "organization_id": "e2e-org",
        "created": "2026-09-30T00:00:00Z",
        "last_modified": "2026-09-30T00:00:00Z",
    }


def run_e2e(pg_bin: Path) -> dict[str, object]:
    initdb = _exe(pg_bin, "initdb")
    pg_ctl = _exe(pg_bin, "pg_ctl")
    root = Path(tempfile.mkdtemp(prefix="breachscope-real-postgres-e2e-"))
    _grant_windows_temp_acl(root)
    data = root / "data"
    sqlite_path = root / "source.sqlite"
    port = _free_port()
    started = False

    result: dict[str, object] = {
        "status": "started",
        "cluster_isolation": "ephemeral_localhost_only",
        "cluster_path_removed": False,
        "system_postgres_service_modified": False,
    }

    try:
        init_args = [
            str(initdb),
            "-D",
            str(data),
            "-U",
            ADMIN,
            "-A",
            "trust",
            "--encoding=UTF8",
            "--locale=C",
        ]
        subprocess.run(
            init_args,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        result["initdb"] = "PASS"

        subprocess.run(
            [
                str(pg_ctl),
                "-D",
                str(data),
                "-l",
                str(root / "postgres.log"),
                "-o",
                f"-p {port} -h 127.0.0.1",
                "-w",
                "start",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=180,
        )
        started = True
        result["server_start"] = "PASS"

        admin_url = make_conninfo(
            host="127.0.0.1",
            port=port,
            dbname="postgres",
            user=ADMIN,
        )
        with psycopg.connect(admin_url, autocommit=True) as conn:
            result["server_version"] = str(
                conn.execute("SHOW server_version").fetchone()[0]
            )
            conn.execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DBNAME))
            )

        url = make_conninfo(
            host="127.0.0.1",
            port=port,
            dbname=DBNAME,
            user=ADMIN,
        )
        first = _store(url)
        second = _store(url)

        assert first.load_users() == []
        assert first.load_groups() == []

        base_user = _user("u-base", "base@example.test")
        base_group = _group("g-base", "Base Group", ["u-base"])
        with first.mutation():
            first.save_users([base_user])
            first.save_groups([base_group])

        assert second.load_users() == [base_user]
        assert second.load_groups() == [base_group]
        result["cross_instance_shared_state"] = "PASS"

        with first.snapshot():
            assert first.load_users() == [base_user]
            assert first.load_groups() == [base_group]
        result["repeatable_read_snapshot"] = "PASS"

        try:
            with first.mutation():
                first.save_users(
                    [base_user, _user("u-rollback", "rollback@example.test")]
                )
                raise RuntimeError("rollback-e2e")
        except RuntimeError as exc:
            assert str(exc) == "rollback-e2e"
        assert second.load_users() == [base_user]
        result["transaction_rollback"] = "PASS"

        state = {"active": 0, "max_active": 0}
        guard = threading.Lock()
        barrier = threading.Barrier(2)
        errors: list[str] = []

        def worker(which: str, store: ScimIdentityStore) -> None:
            try:
                barrier.wait(timeout=5)
                with store.mutation():
                    with guard:
                        state["active"] += 1
                        state["max_active"] = max(
                            state["max_active"],
                            state["active"],
                        )
                    rows = store.load_users()
                    time.sleep(0.25)
                    rows.append(
                        _user(f"u-{which}", f"{which}@example.test")
                    )
                    store.save_users(rows)
                    with guard:
                        state["active"] -= 1
            except Exception as exc:  # pragma: no cover - integration path
                errors.append(f"{type(exc).__name__}: {exc}")

        threads = [
            threading.Thread(target=worker, args=("one", first)),
            threading.Thread(target=worker, args=("two", second)),
        ]
        started_at = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        elapsed = time.monotonic() - started_at

        assert not any(thread.is_alive() for thread in threads)
        assert errors == []
        assert {
            row["id"] for row in second.load_users()
        } == {"u-base", "u-one", "u-two"}
        assert state["max_active"] == 1
        assert elapsed >= 0.45
        result["advisory_lock_two_store_serialization"] = "PASS"
        result["advisory_lock_max_simultaneous_critical_sections"] = 1
        result["advisory_lock_elapsed_seconds"] = round(elapsed, 3)

        with first.mutation():
            first.save_groups([])
            first.save_users([])

        sqlite_cfg = ScimStoreConfig(
            backend="sqlite",
            user_path=root / "source-users.json",
            group_path=root / "source-groups.json",
            database_path=sqlite_path,
        )
        sqlite_store = sqlite_cfg.build()
        migration_users = [
            _user("u-m1", "m1@example.test"),
            _user("u-m2", "m2@example.test"),
        ]
        migration_groups = [
            _group("g-m1", "Migration Group", ["u-m1", "u-m2"]),
        ]
        with sqlite_store.mutation():
            sqlite_store.save_users(migration_users)
            sqlite_store.save_groups(migration_groups)

        pg_cfg = ScimStoreConfig(
            backend="postgres",
            user_path=Path("unused-users.json"),
            group_path=Path("unused-groups.json"),
            database_path=Path("unused.db"),
            database_url=url,
        )
        migrated = migrate_scim_identity_store(sqlite_cfg, pg_cfg)
        assert migrated["success"] is True
        assert migrated["verified"] is True
        assert migrated["users"] == 2
        assert migrated["groups"] == 1
        assert migrated["source_sha256"] == migrated["target_sha256"]
        assert second.load_users() == migration_users
        assert second.load_groups() == migration_groups
        result["sqlite_to_postgres_migration"] = "PASS"
        result["migration_digest_verified"] = True

        with psycopg.connect(url) as conn:
            table_count = conn.execute(
                """
                SELECT count(*)
                FROM information_schema.tables
                WHERE table_schema='public'
                  AND table_name IN (
                      'scim_users',
                      'scim_groups',
                      'scim_group_members'
                  )
                """
            ).fetchone()[0]
            assert table_count == 3
            locked = conn.execute(
                "SELECT pg_try_advisory_xact_lock(%s)",
                (0x425343494D,),
            ).fetchone()[0]
            assert locked is True
            conn.rollback()

        result["real_schema_tables"] = 3
        result["real_advisory_lock_function"] = "PASS"
        result["status"] = "PASS"
    finally:
        if started:
            try:
                subprocess.run(
                    [
                        str(pg_ctl),
                        "-D",
                        str(data),
                        "-m",
                        "fast",
                        "-w",
                        "stop",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=180,
                )
                result["server_stop"] = "PASS"
            except Exception as exc:  # pragma: no cover - cleanup path
                result["server_stop"] = f"FAIL:{type(exc).__name__}"
        try:
            shutil.rmtree(root)
            result["cluster_path_removed"] = not root.exists()
        except Exception as exc:  # pragma: no cover - cleanup path
            result["cluster_path_removed"] = False
            result["cleanup_error"] = f"{type(exc).__name__}: {exc}"

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run a real PostgreSQL SCIM backend E2E in an isolated "
            "ephemeral localhost-only cluster."
        )
    )
    parser.add_argument(
        "--pg-bin",
        default="",
        help="Directory containing initdb and pg_ctl.",
    )
    args = parser.parse_args()

    try:
        result = run_e2e(_pg_bin(args.pg_bin))
    except Exception as exc:
        payload = {
            "status": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 2

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if (
        result.get("status") == "PASS"
        and result.get("cluster_path_removed") is True
        and result.get("server_stop") == "PASS"
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
