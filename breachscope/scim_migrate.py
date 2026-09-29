"""CLI for migrating BreachScope SCIM identity storage."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from api.services.scim_migration import (
    ScimMigrationError,
    ScimStoreConfig,
    migrate_scim_identity_store,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Migrate BreachScope SCIM identity state between "
            "JSON, SQLite, and PostgreSQL backends."
        )
    )
    parser.add_argument(
        "--source-backend",
        required=True,
        choices=["json", "sqlite", "postgres"],
    )
    parser.add_argument(
        "--target-backend",
        required=True,
        choices=["json", "sqlite", "postgres"],
    )
    parser.add_argument(
        "--source-user-path",
        default="~/.breachscope/scim_users.json",
    )
    parser.add_argument(
        "--source-group-path",
        default="~/.breachscope/scim_groups.json",
    )
    parser.add_argument(
        "--source-database-path",
        default="~/.breachscope/scim_identity.db",
    )
    parser.add_argument(
        "--target-user-path",
        default="~/.breachscope/scim_users.json",
    )
    parser.add_argument(
        "--target-group-path",
        default="~/.breachscope/scim_groups.json",
    )
    parser.add_argument(
        "--target-database-path",
        default="~/.breachscope/scim_identity.db",
    )
    parser.add_argument(
        "--source-database-url-env",
        default="BS_SCIM_SOURCE_DATABASE_URL",
        help=(
            "Environment variable containing the source PostgreSQL URL. "
            "The URL itself is never accepted as a CLI argument."
        ),
    )
    parser.add_argument(
        "--target-database-url-env",
        default="BS_SCIM_TARGET_DATABASE_URL",
        help=(
            "Environment variable containing the target PostgreSQL URL. "
            "The URL itself is never accepted as a CLI argument."
        ),
    )
    parser.add_argument(
        "--backup-dir",
        default="~/.breachscope/scim-migration-backups",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help=(
            "Allow replacement of a non-empty target after writing "
            "a snapshot backup."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate source and target without writing target data.",
    )
    return parser


def _database_url(
    backend: str,
    env_name: str,
) -> str:
    if backend != "postgres":
        return ""
    name = str(env_name or "").strip()
    if not name:
        raise ScimMigrationError(
            "PostgreSQL migration requires a database URL "
            "environment-variable name."
        )
    value = str(os.getenv(name, "") or "").strip()
    if not value:
        raise ScimMigrationError(
            f"PostgreSQL migration requires environment variable {name}."
        )
    return value


def _config(
    *,
    backend: str,
    user_path: str,
    group_path: str,
    database_path: str,
    database_url_env: str,
) -> ScimStoreConfig:
    return ScimStoreConfig(
        backend=backend,
        user_path=Path(user_path).expanduser(),
        group_path=Path(group_path).expanduser(),
        database_path=Path(database_path).expanduser(),
        database_url=_database_url(
            backend,
            database_url_env,
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        source = _config(
            backend=args.source_backend,
            user_path=args.source_user_path,
            group_path=args.source_group_path,
            database_path=args.source_database_path,
            database_url_env=args.source_database_url_env,
        )
        target = _config(
            backend=args.target_backend,
            user_path=args.target_user_path,
            group_path=args.target_group_path,
            database_path=args.target_database_path,
            database_url_env=args.target_database_url_env,
        )
        result = migrate_scim_identity_store(
            source,
            target,
            replace=args.replace,
            dry_run=args.dry_run,
            backup_dir=Path(args.backup_dir),
        )
    except ScimMigrationError as exc:
        print(
            json.dumps(
                {
                    "success": False,
                    "error": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
