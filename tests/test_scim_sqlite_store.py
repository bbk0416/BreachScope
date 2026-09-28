from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services.scim_directory import (
    BREACHSCOPE_GROUP_SCHEMA,
    SCIM_BULK_REQUEST_SCHEMA,
    SCIM_PATCH_SCHEMA,
    ScimDirectoryError,
    ScimUserDirectory,
)


SCIM_TOKEN = "q" * 40
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"


def _configure_sqlite(
    tmp_path: Path,
    monkeypatch,
) -> Path:
    for name in (
        "BS_API_KEY",
        "BS_ORGANIZATION_API_KEYS",
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
        "BS_OIDC_ISSUER_URL",
        "BS_OIDC_CLIENT_ID",
        "BS_OIDC_REDIRECT_URI",
        "BS_SCIM_BEARER_TOKEN",
        "BS_SCIM_STORAGE_BACKEND",
        "BS_SCIM_DATABASE_PATH",
        "BS_SCIM_USER_STORE_PATH",
        "BS_SCIM_GROUP_STORE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)

    database_path = tmp_path / "scim_identity.db"
    monkeypatch.setenv("BS_SCIM_BEARER_TOKEN", SCIM_TOKEN)
    monkeypatch.setenv("BS_SCIM_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv(
        "BS_SCIM_DATABASE_PATH",
        str(database_path),
    )
    monkeypatch.setenv(
        "BS_SCIM_USER_STORE_PATH",
        str(tmp_path / "unused_users.json"),
    )
    monkeypatch.setenv(
        "BS_SCIM_GROUP_STORE_PATH",
        str(tmp_path / "unused_groups.json"),
    )
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    return database_path


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {SCIM_TOKEN}"}


def _user_payload(
    name: str,
    external_id: str,
) -> dict:
    return {
        "schemas": [USER_SCHEMA],
        "userName": name,
        "externalId": external_id,
        "active": True,
    }


def _group_payload(
    name: str,
    members: list[dict],
    *,
    role: str = "",
    organization_id: str = "",
) -> dict:
    payload: dict = {
        "schemas": [GROUP_SCHEMA],
        "displayName": name,
        "members": members,
    }
    if role or organization_id:
        payload["schemas"].append(BREACHSCOPE_GROUP_SCHEMA)
        payload[BREACHSCOPE_GROUP_SCHEMA] = {
            "role": role,
            "organizationId": organization_id,
        }
    return payload


def test_sqlite_store_persists_nested_identity_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database_path = _configure_sqlite(tmp_path, monkeypatch)
    client = TestClient(app)

    user_response = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(
            "sqlite-user@example.test",
            "sqlite-subject",
        ),
    )
    assert user_response.status_code == 201, user_response.text
    user_id = user_response.json()["id"]

    child_response = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            "SQLite Child",
            [{"value": user_id, "type": "User"}],
        ),
    )
    assert child_response.status_code == 201, child_response.text
    child_id = child_response.json()["id"]

    parent_response = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            "SQLite Operators",
            [{"value": child_id, "type": "Group"}],
            role="operator",
            organization_id="sqlite-org",
        ),
    )
    assert parent_response.status_code == 201, parent_response.text
    parent_id = parent_response.json()["id"]

    assert ScimUserDirectory().oidc_identity(
        "sqlite-subject"
    ) == ("operator", "sqlite-org")

    assert database_path.exists()
    assert not (tmp_path / "unused_users.json").exists()
    assert not (tmp_path / "unused_groups.json").exists()

    with sqlite3.connect(database_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "scim_users",
            "scim_groups",
            "scim_group_members",
        }.issubset(tables)
        assert conn.execute(
            "SELECT COUNT(*) FROM scim_users"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM scim_groups"
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT COUNT(*) FROM scim_group_members"
        ).fetchone()[0] == 2

    fresh_directory = ScimUserDirectory()
    assert fresh_directory.stats() == {
        "total_users": 1,
        "active_users": 1,
        "authorized_users": 1,
        "total_groups": 2,
    }
    assert fresh_directory.oidc_identity(
        "sqlite-subject"
    ) == ("operator", "sqlite-org")

    deleted = client.delete(
        f"/api/scim/v2/Groups/{child_id}",
        headers=_headers(),
    )
    assert deleted.status_code == 204

    parent = client.get(
        f"/api/scim/v2/Groups/{parent_id}",
        headers=_headers(),
    )
    assert parent.status_code == 200
    assert parent.json()["members"] == []
    assert ScimUserDirectory().oidc_identity(
        "sqlite-subject"
    ) is None


def test_sqlite_store_supports_patch_etag_and_delete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_sqlite(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(
            "sqlite-patch@example.test",
            "sqlite-patch-subject",
        ),
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    patched = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers={
            **_headers(),
            "If-Match": created.headers["etag"],
        },
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": "active",
                    "value": False,
                }
            ],
        },
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["active"] is False

    stale = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers={
            **_headers(),
            "If-Match": created.headers["etag"],
        },
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": "active",
                    "value": True,
                }
            ],
        },
    )
    assert stale.status_code == 412

    deleted = client.delete(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
    )
    assert deleted.status_code == 204
    assert client.get(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
    ).status_code == 404


def test_sqlite_store_supports_bulk_forward_references(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_sqlite(tmp_path, monkeypatch)
    client = TestClient(app)

    response = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Groups",
                    "bulkId": "group",
                    "data": _group_payload(
                        "SQLite Bulk Operators",
                        [
                            {
                                "value": "bulkId:user",
                                "type": "User",
                            }
                        ],
                        role="operator",
                        organization_id="sqlite-bulk",
                    ),
                },
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "user",
                    "data": _user_payload(
                        "sqlite-bulk@example.test",
                        "sqlite-bulk-subject",
                    ),
                },
            ],
        },
    )
    assert response.status_code == 200, response.text
    assert [
        row["status"]
        for row in response.json()["Operations"]
    ] == ["201", "201"]
    assert ScimUserDirectory().oidc_identity(
        "sqlite-bulk-subject"
    ) == ("operator", "sqlite-bulk")


def test_invalid_scim_storage_backend_fails_closed() -> None:
    with pytest.raises(
        ScimDirectoryError,
        match="must be json or sqlite",
    ):
        ScimUserDirectory(
            env={"BS_SCIM_STORAGE_BACKEND": "postgres"},
        )
