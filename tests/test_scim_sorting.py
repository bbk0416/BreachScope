from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app


SCIM_TOKEN = "o" * 40
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
        "BS_SCIM_STORAGE_BACKEND",
        "BS_SCIM_DATABASE_PATH",
        "BS_SCIM_DATABASE_URL",
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


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {SCIM_TOKEN}"}


def _create_user(
    client: TestClient,
    *,
    user_name: str,
    external_id: str,
) -> dict:
    response = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json={
            "schemas": [USER_SCHEMA],
            "userName": user_name,
            "externalId": external_id,
            "active": True,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_group(
    client: TestClient,
    *,
    display_name: str,
) -> dict:
    response = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json={
            "schemas": [GROUP_SCHEMA],
            "displayName": display_name,
            "members": [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_service_provider_config_advertises_sorting(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    response = client.get(
        "/api/scim/v2/ServiceProviderConfig",
        headers=_headers(),
    )
    assert response.status_code == 200
    assert response.json()["sort"] == {"supported": True}


def test_user_sorting_precedes_pagination(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    for user_name, external_id in (
        ("Zulu@example.test", "subject-c"),
        ("alpha@example.test", "Subject-A"),
        ("Bravo@example.test", "subject-b"),
    ):
        _create_user(
            client,
            user_name=user_name,
            external_id=external_id,
        )

    ascending = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={
            "sortBy": "userName",
            "sortOrder": "ascending",
        },
    )
    assert ascending.status_code == 200
    assert [
        row["userName"]
        for row in ascending.json()["Resources"]
    ] == [
        "alpha@example.test",
        "Bravo@example.test",
        "Zulu@example.test",
    ]

    default_ascending = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={"sortBy": "userName"},
    )
    assert default_ascending.status_code == 200
    assert [
        row["userName"]
        for row in default_ascending.json()["Resources"]
    ] == [
        "alpha@example.test",
        "Bravo@example.test",
        "Zulu@example.test",
    ]

    descending = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={
            "sortBy": "externalId",
            "sortOrder": "descending",
        },
    )
    assert descending.status_code == 200
    assert [
        row["externalId"]
        for row in descending.json()["Resources"]
    ] == [
        "subject-c",
        "subject-b",
        "Subject-A",
    ]

    page = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={
            "sortBy": "userName",
            "sortOrder": "ascending",
            "startIndex": 2,
            "count": 1,
        },
    )
    assert page.status_code == 200
    assert page.json()["totalResults"] == 3
    assert page.json()["itemsPerPage"] == 1
    assert page.json()["Resources"][0]["userName"] == (
        "Bravo@example.test"
    )

    missing = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json={
            "schemas": [USER_SCHEMA],
            "userName": "missing@example.test",
            "active": False,
        },
    )
    assert missing.status_code == 201, missing.text

    external_ascending = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={
            "sortBy": "externalId",
            "sortOrder": "ascending",
        },
    )
    assert external_ascending.status_code == 200
    assert [
        row.get("externalId", "")
        for row in external_ascending.json()["Resources"]
    ] == [
        "Subject-A",
        "subject-b",
        "subject-c",
        "",
    ]

    external_descending = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={
            "sortBy": "externalId",
            "sortOrder": "descending",
        },
    )
    assert external_descending.status_code == 200
    assert [
        row.get("externalId", "")
        for row in external_descending.json()["Resources"]
    ] == [
        "",
        "subject-c",
        "subject-b",
        "Subject-A",
    ]


def test_group_sorting_precedes_pagination(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    for display_name in (
        "Zulu Team",
        "alpha team",
        "Bravo Team",
    ):
        _create_group(
            client,
            display_name=display_name,
        )

    ascending = client.get(
        "/api/scim/v2/Groups",
        headers=_headers(),
        params={
            "sortBy": "displayName",
            "sortOrder": "ascending",
        },
    )
    assert ascending.status_code == 200
    assert [
        row["displayName"]
        for row in ascending.json()["Resources"]
    ] == [
        "alpha team",
        "Bravo Team",
        "Zulu Team",
    ]

    descending = client.get(
        "/api/scim/v2/Groups",
        headers=_headers(),
        params={
            "sortBy": "displayName",
            "sortOrder": "descending",
            "startIndex": 2,
            "count": 1,
        },
    )
    assert descending.status_code == 200
    assert descending.json()["Resources"][0]["displayName"] == (
        "Bravo Team"
    )


def test_invalid_sort_parameters_fail_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    unsupported = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={"sortBy": "emails"},
    )
    assert unsupported.status_code == 400
    assert unsupported.json()["scimType"] == "invalidValue"

    bad_order = client.get(
        "/api/scim/v2/Groups",
        headers=_headers(),
        params={
            "sortBy": "displayName",
            "sortOrder": "sideways",
        },
    )
    assert bad_order.status_code == 400
    assert bad_order.json()["scimType"] == "invalidValue"

    missing_sort_by = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={"sortOrder": "descending"},
    )
    assert missing_sort_by.status_code == 400
    assert missing_sort_by.json()["scimType"] == "invalidValue"
