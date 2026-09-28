from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.scim_directory import (
    BREACHSCOPE_GROUP_SCHEMA,
    SCIM_PATCH_SCHEMA,
    ScimUserDirectory,
)
from api.services.scim_groups import ScimGroupDirectory


SCIM_TOKEN = "t" * 40


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
        "BS_OIDC_ISSUER_URL",
        "https://idp.example.test",
    )
    monkeypatch.setenv("BS_OIDC_CLIENT_ID", "breachscope")
    monkeypatch.setenv(
        "BS_OIDC_REDIRECT_URI",
        "https://breachscope.example.test/api/auth/oidc/callback",
    )
    monkeypatch.setenv(
        "BS_SESSION_SECRET",
        "scim-group-session-secret-1234567890",
    )
    monkeypatch.setenv("BS_COOKIE_SECURE", "0")
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


def _create_user(
    client: TestClient,
    *,
    user_name: str,
    external_id: str,
    role: str = "",
    organization_id: str = "",
) -> dict:
    payload: dict = {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User"
        ],
        "userName": user_name,
        "externalId": external_id,
        "active": True,
    }
    if role or organization_id:
        payload[
            "urn:breachscope:params:scim:schemas:extension:1.0:User"
        ] = {
            "role": role,
            "organizationId": organization_id,
        }
    response = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=payload,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _group_payload(
    *,
    display_name: str,
    members: list[str],
    role: str = "",
    organization_id: str = "",
) -> dict:
    payload: dict = {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:Group"
        ],
        "displayName": display_name,
        "members": [{"value": member} for member in members],
    }
    if role or organization_id:
        payload["schemas"].append(BREACHSCOPE_GROUP_SCHEMA)
        payload[BREACHSCOPE_GROUP_SCHEMA] = {
            "role": role,
            "organizationId": organization_id,
        }
    return payload


def test_scim_group_discovery_and_crud(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    user_a = _create_user(
        client,
        user_name="alice@example.test",
        external_id="sub-alice",
    )
    user_b = _create_user(
        client,
        user_name="bob@example.test",
        external_id="sub-bob",
    )

    resource_types = client.get(
        "/api/scim/v2/ResourceTypes",
        headers=_headers(),
    )
    assert resource_types.status_code == 200
    assert resource_types.json()["totalResults"] == 2
    assert {
        row["id"]
        for row in resource_types.json()["Resources"]
    } == {"User", "Group"}

    group_type = client.get(
        "/api/scim/v2/ResourceTypes/Group",
        headers=_headers(),
    )
    assert group_type.status_code == 200
    assert group_type.json()["endpoint"] == "/Groups"

    schemas = client.get(
        "/api/scim/v2/Schemas",
        headers=_headers(),
    )
    assert schemas.status_code == 200
    assert schemas.json()["totalResults"] == 4

    created = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="SOC Blue Operators",
            members=[user_a["id"]],
            role="operator",
            organization_id="soc-blue",
        ),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    group_id = body["id"]
    etag = created.headers["etag"]
    assert body["displayName"] == "SOC Blue Operators"
    assert [row["value"] for row in body["members"]] == [
        user_a["id"]
    ]
    assert body["members"][0]["display"] == "alice@example.test"
    assert body[BREACHSCOPE_GROUP_SCHEMA] == {
        "role": "operator",
        "organizationId": "soc-blue",
    }

    filtered = client.get(
        "/api/scim/v2/Groups",
        headers=_headers(),
        params={"filter": 'displayName eq "soc blue operators"'},
    )
    assert filtered.status_code == 200
    assert filtered.json()["totalResults"] == 1
    assert filtered.json()["Resources"][0]["id"] == group_id

    stale = client.patch(
        f"/api/scim/v2/Groups/{group_id}",
        headers={**_headers(), "If-Match": 'W/"stale"'},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": user_b["id"]}],
                }
            ],
        },
    )
    assert stale.status_code == 412

    added = client.patch(
        f"/api/scim/v2/Groups/{group_id}",
        headers={**_headers(), "If-Match": etag},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": user_b["id"]}],
                }
            ],
        },
    )
    assert added.status_code == 200, added.text
    assert {
        row["value"]
        for row in added.json()["members"]
    } == {user_a["id"], user_b["id"]}

    removed = client.patch(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "remove",
                    "path": (
                        f'members[value eq "{user_a["id"]}"]'
                    ),
                }
            ],
        },
    )
    assert removed.status_code == 200, removed.text
    assert [row["value"] for row in removed.json()["members"]] == [
        user_b["id"]
    ]

    replaced = client.put(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json=_group_payload(
            display_name="SOC Blue Reviewers",
            members=[user_b["id"]],
            role="reviewer",
            organization_id="soc-blue",
        ),
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["displayName"] == "SOC Blue Reviewers"
    assert (
        replaced.json()[BREACHSCOPE_GROUP_SCHEMA]["role"]
        == "reviewer"
    )

    duplicate = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="soc blue reviewers",
            members=[],
        ),
    )
    assert duplicate.status_code == 409

    unknown_member = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="Bad Members",
            members=["missing-user"],
        ),
    )
    assert unknown_member.status_code == 400

    deleted = client.delete(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
    )
    assert deleted.status_code == 204
    assert client.get(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
    ).status_code == 404

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    group_events = [
        row
        for row in events
        if str(row.get("action") or "").startswith("scim.group.")
    ]
    assert [row["action"] for row in group_events] == [
        "scim.group.create",
        "scim.group.patch",
        "scim.group.patch",
        "scim.group.replace",
        "scim.group.delete",
    ]
    assert group_events[0]["organization_id"] == "soc-blue"
    assert SCIM_TOKEN not in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8"
    )


def test_group_assignment_is_oidc_authority_and_lifecycle_is_immediate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    user = _create_user(
        client,
        user_name="group-user@example.test",
        external_id="group-subject",
    )
    group = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="Operators",
            members=[user["id"]],
            role="operator",
            organization_id="org-a",
        ),
    )
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]

    assert ScimUserDirectory().oidc_identity(
        "group-subject"
    ) == ("operator", "org-a")

    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:group-subject",
            role="operator",
            authn="oidc",
            organization_id="org-a",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    changed_role = client.patch(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": BREACHSCOPE_GROUP_SCHEMA + ":role",
                    "value": "reviewer",
                }
            ],
        },
    )
    assert changed_role.status_code == 200
    assert client.get("/api/cases").status_code == 401

    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:group-subject",
            role="reviewer",
            authn="oidc",
            organization_id="org-a",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    changed_org = client.patch(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": (
                        BREACHSCOPE_GROUP_SCHEMA
                        + ":organizationId"
                    ),
                    "value": "org-b",
                }
            ],
        },
    )
    assert changed_org.status_code == 200
    assert client.get("/api/cases").status_code == 401

    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:group-subject",
            role="reviewer",
            authn="oidc",
            organization_id="org-b",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    removed = client.patch(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "remove",
                    "path": (
                        f'members[value eq "{user["id"]}"]'
                    ),
                }
            ],
        },
    )
    assert removed.status_code == 200
    assert ScimUserDirectory().oidc_identity(
        "group-subject"
    ) is None
    assert client.get("/api/cases").status_code == 401

    readded = client.patch(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": user["id"]}],
                }
            ],
        },
    )
    assert readded.status_code == 200
    assert ScimUserDirectory().oidc_identity(
        "group-subject"
    ) == ("reviewer", "org-b")

    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:group-subject",
            role="reviewer",
            authn="oidc",
            organization_id="org-b",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    assert client.delete(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
    ).status_code == 204
    assert client.get("/api/cases").status_code == 401


def test_conflicting_direct_and_group_assignments_fail_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    user = _create_user(
        client,
        user_name="conflict@example.test",
        external_id="conflict-subject",
        role="operator",
        organization_id="org-a",
    )
    same = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="Same Assignment",
            members=[user["id"]],
            role="operator",
            organization_id="org-a",
        ),
    )
    assert same.status_code == 201
    assert ScimUserDirectory().oidc_identity(
        "conflict-subject"
    ) == ("operator", "org-a")

    conflicting = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="Conflicting Assignment",
            members=[user["id"]],
            role="reviewer",
            organization_id="org-a",
        ),
    )
    assert conflicting.status_code == 201
    assert ScimUserDirectory().oidc_identity(
        "conflict-subject"
    ) is None


def test_deleting_user_removes_group_membership_reference(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    user = _create_user(
        client,
        user_name="cleanup@example.test",
        external_id="cleanup-subject",
    )
    group = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="Cleanup Group",
            members=[user["id"]],
            role="operator",
            organization_id="org-a",
        ),
    )
    assert group.status_code == 201
    group_id = group.json()["id"]

    assert client.delete(
        f"/api/scim/v2/Users/{user['id']}",
        headers=_headers(),
    ).status_code == 204

    current = client.get(
        f"/api/scim/v2/Groups/{group_id}",
        headers=_headers(),
    )
    assert current.status_code == 200
    assert current.json()["members"] == []


def test_group_assignment_requires_role_and_organization_pair(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    user = _create_user(
        client,
        user_name="partial-group@example.test",
        external_id="partial-group-subject",
    )
    response = client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json={
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group",
                BREACHSCOPE_GROUP_SCHEMA,
            ],
            "displayName": "Partial Group",
            "members": [{"value": user["id"]}],
            BREACHSCOPE_GROUP_SCHEMA: {
                "role": "operator",
            },
        },
    )
    assert response.status_code == 400
    assert "both role and organizationId" in response.json()["detail"]


def test_group_store_is_separate_from_user_store(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    user = _create_user(
        client,
        user_name="separate@example.test",
        external_id="separate-subject",
    )
    assert client.post(
        "/api/scim/v2/Groups",
        headers=_headers(),
        json=_group_payload(
            display_name="Separate Store",
            members=[user["id"]],
            role="author",
            organization_id="org-z",
        ),
    ).status_code == 201

    user_payload = json.loads(
        (tmp_path / "scim_users.json").read_text(encoding="utf-8")
    )
    group_payload = json.loads(
        (tmp_path / "scim_groups.json").read_text(encoding="utf-8")
    )
    assert "users" in user_payload
    assert "groups" not in user_payload
    assert "groups" in group_payload
    assert len(group_payload["groups"]) == 1
