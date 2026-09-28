from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.services.scim_directory import (
    BREACHSCOPE_GROUP_SCHEMA,
    SCIM_BULK_REQUEST_SCHEMA,
    SCIM_BULK_RESPONSE_SCHEMA,
    SCIM_PATCH_SCHEMA,
)


SCIM_TOKEN = "b" * 40
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"


def _configure(tmp_path: Path, monkeypatch) -> None:
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
        "BS_SCIM_USER_STORE_PATH",
        "BS_SCIM_GROUP_STORE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setenv("BS_SCIM_BEARER_TOKEN", SCIM_TOKEN)
    monkeypatch.setenv(
        "BS_SCIM_USER_STORE_PATH",
        str(tmp_path / "scim_users.json"),
    )
    monkeypatch.setenv(
        "BS_SCIM_GROUP_STORE_PATH",
        str(tmp_path / "scim_groups.json"),
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


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {SCIM_TOKEN}"}


def _user_data(
    name: str,
    external_id: str,
) -> dict:
    return {
        "schemas": [USER_SCHEMA],
        "userName": name,
        "externalId": external_id,
        "active": True,
    }


def test_scim_bulk_discovery_and_bearer_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    config = client.get(
        "/api/scim/v2/ServiceProviderConfig",
        headers=_headers(),
    )
    assert config.status_code == 200
    assert config.json()["bulk"] == {
        "supported": True,
        "maxOperations": 100,
        "maxPayloadSize": 1_048_576,
    }

    missing = client.post(
        "/api/scim/v2/Bulk",
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "Operations": [],
        },
    )
    assert missing.status_code == 401


def test_scim_bulk_resolves_forward_bulk_id_and_audits(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    payload = {
        "schemas": [SCIM_BULK_REQUEST_SCHEMA],
        "Operations": [
            {
                "method": "POST",
                "path": "/Groups",
                "bulkId": "group-1",
                "data": {
                    "schemas": [
                        GROUP_SCHEMA,
                        BREACHSCOPE_GROUP_SCHEMA,
                    ],
                    "displayName": "SOC Blue Operators",
                    "members": [{"value": "bulkId:user-1"}],
                    BREACHSCOPE_GROUP_SCHEMA: {
                        "role": "operator",
                        "organizationId": "soc-blue",
                    },
                },
            },
            {
                "method": "POST",
                "path": "/Users",
                "bulkId": "user-1",
                "data": _user_data(
                    "alice@example.test",
                    "sub-alice",
                ),
            },
        ],
    }
    response = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json=payload,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schemas"] == [SCIM_BULK_RESPONSE_SCHEMA]
    assert [row["status"] for row in body["Operations"]] == [
        "201",
        "201",
    ]
    group_result, user_result = body["Operations"]
    assert group_result["bulkId"] == "group-1"
    assert user_result["bulkId"] == "user-1"
    assert group_result["location"].endswith(
        "/api/scim/v2/Groups/" + group_result["location"].rsplit("/", 1)[-1]
    )
    assert user_result["version"].startswith('W/"')

    users = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
    ).json()["Resources"]
    groups = client.get(
        "/api/scim/v2/Groups",
        headers=_headers(),
    ).json()["Resources"]
    assert len(users) == 1
    assert len(groups) == 1
    assert groups[0]["members"][0]["value"] == users[0]["id"]

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    actions = [row["action"] for row in events]
    assert actions == [
        "scim.user.create",
        "scim.group.create",
    ]
    assert SCIM_TOKEN not in (
        tmp_path / "audit.jsonl"
    ).read_text(encoding="utf-8")


def test_scim_bulk_put_patch_delete_and_version_checks(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=_user_data(
            "alice@example.test",
            "sub-alice",
        ),
    )
    assert created.status_code == 201
    user = created.json()
    user_id = user["id"]
    etag = created.headers["etag"]

    response = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "PATCH",
                    "path": f"/Users/{user_id}",
                    "version": 'W/"stale"',
                    "data": {
                        "schemas": [SCIM_PATCH_SCHEMA],
                        "Operations": [
                            {
                                "op": "replace",
                                "path": "active",
                                "value": False,
                            }
                        ],
                    },
                },
                {
                    "method": "PUT",
                    "path": f"/Users/{user_id}",
                    "version": etag,
                    "data": _user_data(
                        "alice-renamed@example.test",
                        "sub-alice",
                    ),
                },
            ],
        },
    )
    assert response.status_code == 200
    operations = response.json()["Operations"]
    assert operations[0]["status"] == "412"
    assert operations[0]["response"]["status"] == "412"
    assert operations[1]["status"] == "200"

    current = client.get(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
    )
    assert current.status_code == 200
    assert current.json()["userName"] == "alice-renamed@example.test"

    deleted = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "DELETE",
                    "path": f"/Users/{user_id}",
                    "version": current.headers["etag"],
                }
            ],
        },
    )
    assert deleted.status_code == 200
    assert deleted.json()["Operations"][0]["status"] == "204"
    assert client.get(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
    ).status_code == 404


def test_scim_bulk_fail_on_errors_stops_remaining_operations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    seed = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=_user_data(
            "duplicate@example.test",
            "sub-existing",
        ),
    )
    assert seed.status_code == 201

    response = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "failOnErrors": 1,
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "duplicate",
                    "data": _user_data(
                        "duplicate@example.test",
                        "sub-new",
                    ),
                },
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "must-not-run",
                    "data": _user_data(
                        "later@example.test",
                        "sub-later",
                    ),
                },
            ],
        },
    )
    assert response.status_code == 200
    operations = response.json()["Operations"]
    assert len(operations) == 1
    assert operations[0]["status"] == "409"
    assert operations[0]["bulkId"] == "duplicate"

    listing = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
    ).json()
    assert listing["totalResults"] == 1


def test_scim_bulk_rejects_invalid_request_and_limits(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    wrong_schema = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [USER_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "u1",
                    "data": _user_data(
                        "a@example.test",
                        "sub-a",
                    ),
                }
            ],
        },
    )
    assert wrong_schema.status_code == 400
    assert wrong_schema.json()["scimType"] == "invalidSyntax"

    duplicate_bulk_id = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "same",
                    "data": _user_data(
                        "a@example.test",
                        "sub-a",
                    ),
                },
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "same",
                    "data": _user_data(
                        "b@example.test",
                        "sub-b",
                    ),
                },
            ],
        },
    )
    assert duplicate_bulk_id.status_code == 400
    assert duplicate_bulk_id.json()["scimType"] == "uniqueness"

    too_many = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": f"u-{index}",
                    "data": _user_data(
                        f"user-{index}@example.test",
                        f"sub-{index}",
                    ),
                }
                for index in range(101)
            ],
        },
    )
    assert too_many.status_code == 413
    assert "maxOperations (100)" in too_many.json()["detail"]

    oversized = client.post(
        "/api/scim/v2/Bulk",
        headers={
            **_headers(),
            "Content-Type": "application/scim+json",
        },
        content=(
            b'{"schemas":["'
            + SCIM_BULK_REQUEST_SCHEMA.encode("utf-8")
            + b'"],"Operations":[],"padding":"'
            + (b"x" * 1_048_576)
            + b'"}'
        ),
    )
    assert oversized.status_code == 413
    assert "maxPayloadSize (1048576)" in oversized.json()["detail"]


def test_scim_bulk_does_not_rewrite_non_reference_user_strings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    response = client.post(
        "/api/scim/v2/Bulk",
        headers=_headers(),
        json={
            "schemas": [SCIM_BULK_REQUEST_SCHEMA],
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "user-1",
                    "data": _user_data(
                        "bulkId:literal-user-name",
                        "bulkId:literal-external-id",
                    ),
                }
            ],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["Operations"][0]["status"] == "201"

    listing = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
    ).json()["Resources"]
    assert listing[0]["userName"] == "bulkId:literal-user-name"
    assert listing[0]["externalId"] == "bulkId:literal-external-id"


def test_scim_bulk_reports_unresolved_reference_without_partial_create(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
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
                    "bulkId": "g1",
                    "data": {
                        "schemas": [GROUP_SCHEMA],
                        "displayName": "Broken group",
                        "members": [{"value": "bulkId:missing"}],
                    },
                }
            ],
        },
    )
    assert response.status_code == 200
    operation = response.json()["Operations"][0]
    assert operation["status"] == "400"
    assert operation["response"]["status"] == "400"
    assert client.get(
        "/api/scim/v2/Groups",
        headers=_headers(),
    ).json()["totalResults"] == 0
