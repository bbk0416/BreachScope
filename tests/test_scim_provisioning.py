from __future__ import annotations

import json
import time
import urllib.parse
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from api.routers import auth
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services import oidc_auth
from api.services.scim_directory import (
    BREACHSCOPE_USER_SCHEMA,
    SCIM_PATCH_SCHEMA,
    ScimUserDirectory,
)


SCIM_TOKEN = "s" * 40


def _clear(monkeypatch) -> None:
    for name in (
        "BS_API_KEY",
        "BS_ORGANIZATION_API_KEYS",
        "BS_ORGANIZATION_RBAC_POLICIES",
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
        "BS_OIDC_ISSUER_URL",
        "BS_OIDC_CLIENT_ID",
        "BS_OIDC_CLIENT_SECRET",
        "BS_OIDC_REDIRECT_URI",
        "BS_OIDC_SCOPES",
        "BS_OIDC_ROLE_CLAIM",
        "BS_OIDC_ORGANIZATION_CLAIM",
        "BS_OIDC_DEFAULT_ROLE",
        "BS_OIDC_ADMIN_VALUES",
        "BS_OIDC_AUTHOR_VALUES",
        "BS_OIDC_REVIEWER_VALUES",
        "BS_OIDC_OPERATOR_VALUES",
        "BS_OIDC_TOKEN_AUTH_METHOD",
        "BS_SCIM_BEARER_TOKEN",
        "BS_SCIM_USER_STORE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)


def _configure(tmp_path: Path, monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("BS_SCIM_BEARER_TOKEN", SCIM_TOKEN)
    monkeypatch.setenv(
        "BS_SCIM_USER_STORE_PATH",
        str(tmp_path / "scim_users.json"),
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
        "scim-session-secret-long-enough-123456",
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


def _user_payload(
    *,
    user_name: str = "alice@example.test",
    external_id: str = "subject-123",
    active: bool = True,
    role: str = "operator",
    organization_id: str = "org-a",
) -> dict:
    return {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            BREACHSCOPE_USER_SCHEMA,
        ],
        "userName": user_name,
        "externalId": external_id,
        "active": active,
        BREACHSCOPE_USER_SCHEMA: {
            "role": role,
            "organizationId": organization_id,
        },
    }


def _metadata() -> dict[str, str]:
    return {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "jwks_uri": "https://idp.example.test/jwks",
    }


def _start_oidc(
    client: TestClient,
    monkeypatch,
    *,
    subject: str,
) -> object:
    monkeypatch.setattr(auth, "fetch_discovery", lambda config: _metadata())
    monkeypatch.setattr(
        auth,
        "exchange_code_for_tokens",
        lambda config, metadata, **kwargs: {
            "id_token": "unit-id-token"
        },
    )
    monkeypatch.setattr(
        auth,
        "verify_id_token",
        lambda config, metadata, **kwargs: {
            "sub": subject,
            "groups": ["ignored-by-scim"],
            "exp": int(time.time()) + 600,
        },
    )
    start = client.get(
        "/api/auth/oidc/login?next=/cases",
        follow_redirects=False,
    )
    assert start.status_code == 302
    state = urllib.parse.parse_qs(
        urllib.parse.urlparse(start.headers["location"]).query
    )["state"][0]
    return client.get(
        "/api/auth/oidc/callback",
        params={"code": "code-123", "state": state},
        follow_redirects=False,
    )


def test_scim_discovery_requires_dedicated_bearer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    missing = client.get("/api/scim/v2/ServiceProviderConfig")
    assert missing.status_code == 401
    assert missing.headers["content-type"].startswith(
        "application/scim+json"
    )

    wrong = client.get(
        "/api/scim/v2/ServiceProviderConfig",
        headers={"Authorization": "Bearer wrong"},
    )
    assert wrong.status_code == 401

    response = client.get(
        "/api/scim/v2/ServiceProviderConfig",
        headers=_headers(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["patch"]["supported"] is True
    assert body["filter"]["supported"] is True

    resource_types = client.get(
        "/api/scim/v2/ResourceTypes",
        headers=_headers(),
    )
    assert resource_types.status_code == 200
    assert resource_types.json()["totalResults"] == 1
    user_type = client.get(
        "/api/scim/v2/ResourceTypes/User",
        headers=_headers(),
    )
    assert user_type.status_code == 200
    assert user_type.json()["endpoint"] == "/Users"

    schemas = client.get(
        "/api/scim/v2/Schemas",
        headers=_headers(),
    )
    assert schemas.status_code == 200
    assert schemas.json()["totalResults"] == 2


def test_scim_user_crud_filter_patch_and_audit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(),
    )
    assert created.status_code == 201, created.text
    assert created.headers["etag"].startswith('W/"')
    resource = created.json()
    user_id = resource["id"]
    assert resource["userName"] == "alice@example.test"
    assert resource["externalId"] == "subject-123"
    assert resource["active"] is True
    assert resource["roles"][0]["value"] == "operator"
    assert resource[BREACHSCOPE_USER_SCHEMA]["organizationId"] == "org-a"

    filtered = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={"filter": 'externalId eq "subject-123"'},
    )
    assert filtered.status_code == 200
    assert filtered.json()["totalResults"] == 1
    assert filtered.json()["Resources"][0]["id"] == user_id

    by_name = client.get(
        "/api/scim/v2/Users",
        headers=_headers(),
        params={"filter": 'userName eq "ALICE@example.test"'},
    )
    assert by_name.status_code == 200
    assert by_name.json()["totalResults"] == 1

    duplicate = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(user_name="other@example.test"),
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["scimType"] == "uniqueness"

    patched = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
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

    invalid_path = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": "password",
                    "value": "never-store-this",
                }
            ],
        },
    )
    assert invalid_path.status_code == 400
    assert invalid_path.json()["scimType"] == "invalidPath"

    replaced = client.put(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json=_user_payload(
            user_name="alice-renamed@example.test",
            role="reviewer",
            organization_id="org-b",
        ),
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["id"] == user_id
    assert replaced.json()["roles"][0]["value"] == "reviewer"
    assert (
        replaced.json()[BREACHSCOPE_USER_SCHEMA]["organizationId"]
        == "org-b"
    )

    deleted = client.delete(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
    )
    assert deleted.status_code == 204
    assert client.get(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
    ).status_code == 404

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    scim_events = [
        row
        for row in events
        if str(row.get("action") or "").startswith("scim.user.")
    ]
    assert [row["action"] for row in scim_events] == [
        "scim.user.create",
        "scim.user.patch",
        "scim.user.replace",
        "scim.user.delete",
    ]
    assert all(
        row["actor"] == "scim-provisioner"
        and row["auth_method"] == "scim"
        for row in scim_events
    )
    assert scim_events[0]["organization_id"] == "org-a"
    assert scim_events[-1]["organization_id"] == "org-b"
    assert SCIM_TOKEN not in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8"
    )


def test_scim_active_user_requires_role_and_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    active_missing = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json={
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "userName": "incomplete@example.test",
            "externalId": "subject-incomplete",
            "active": True,
        },
    )
    assert active_missing.status_code == 400

    inactive = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json={
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User"
            ],
            "userName": "incomplete@example.test",
            "externalId": "subject-incomplete",
            "active": False,
        },
    )
    assert inactive.status_code == 201
    user_id = inactive.json()["id"]

    activate_without_assignments = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": True}
            ],
        },
    )
    assert activate_without_assignments.status_code == 400


def test_scim_configuration_allows_oidc_without_claim_role_mapping(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    assert oidc_auth.oidc_is_configured() is True
    config = oidc_auth.configured_oidc_config()
    assert config.default_role == ""
    assert not any(config.role_values.values())


def test_oidc_callback_uses_scim_role_and_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    ScimUserDirectory().create_user(
        _user_payload(role="reviewer", organization_id="soc-blue")
    )

    client = TestClient(app)
    callback = _start_oidc(
        client,
        monkeypatch,
        subject="subject-123",
    )
    assert callback.status_code == 303, callback.text

    status = client.get("/api/auth/status").json()
    assert status["authenticated"] is True
    assert status["session_authn"] == "oidc"
    assert status["session_subject"] == "oidc:subject-123"
    assert status["session_role"] == "reviewer"
    assert status["session_organization_id"] == "soc-blue"
    assert status["scim_provisioning_enabled"] is True
    assert status["scim_oidc_enforced"] is True


def test_oidc_callback_rejects_unprovisioned_or_inactive_scim_user(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    missing = _start_oidc(
        client,
        monkeypatch,
        subject="missing-subject",
    )
    assert missing.status_code == 403

    ScimUserDirectory().create_user(
        _user_payload(
            external_id="inactive-subject",
            active=False,
            role="",
            organization_id="",
        )
    )
    inactive = _start_oidc(
        client,
        monkeypatch,
        subject="inactive-subject",
    )
    assert inactive.status_code == 403


def test_scim_patch_accepts_extension_object_value(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    directory = ScimUserDirectory()
    resource = directory.create_user(_user_payload())
    user_id = resource["id"]
    client = TestClient(app)

    response = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": BREACHSCOPE_USER_SCHEMA,
                    "value": {
                        "role": "author",
                        "organizationId": "org-c",
                    },
                }
            ],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["roles"][0]["value"] == "author"
    assert (
        body[BREACHSCOPE_USER_SCHEMA]["organizationId"]
        == "org-c"
    )


def test_existing_oidc_session_is_revoked_by_scim_lifecycle_changes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    directory = ScimUserDirectory()
    resource = directory.create_user(_user_payload())
    user_id = resource["id"]

    client = TestClient(app)
    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:subject-123",
            role="operator",
            authn="oidc",
            organization_id="org-a",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    role_change = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": (
                        BREACHSCOPE_USER_SCHEMA + ":role"
                    ),
                    "value": "reviewer",
                }
            ],
        },
    )
    assert role_change.status_code == 200
    assert client.get("/api/cases").status_code == 401

    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:subject-123",
            role="reviewer",
            authn="oidc",
            organization_id="org-a",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    org_change = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "path": (
                        BREACHSCOPE_USER_SCHEMA + ":organizationId"
                    ),
                    "value": "org-b",
                }
            ],
        },
    )
    assert org_change.status_code == 200
    assert client.get("/api/cases").status_code == 401

    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:subject-123",
            role="reviewer",
            authn="oidc",
            organization_id="org-b",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    disabled = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": False}
            ],
        },
    )
    assert disabled.status_code == 200
    assert client.get("/api/cases").status_code == 401

    reenabled = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": True}
            ],
        },
    )
    assert reenabled.status_code == 200

    client.cookies.set(
        SESSION_COOKIE_NAME,
        create_session_token(
            subject="oidc:subject-123",
            role="reviewer",
            authn="oidc",
            organization_id="org-b",
        ),
    )
    assert client.get("/api/cases").status_code == 200

    assert client.delete(
        f"/api/scim/v2/Users/{user_id}",
        headers=_headers(),
    ).status_code == 204
    assert client.get("/api/cases").status_code == 401


def test_scim_routes_remain_available_during_production_auth_recovery(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "production")
    monkeypatch.delenv("BS_OIDC_ISSUER_URL", raising=False)
    monkeypatch.delenv("BS_OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("BS_OIDC_REDIRECT_URI", raising=False)

    client = TestClient(app)
    response = client.get(
        "/api/scim/v2/ServiceProviderConfig",
        headers=_headers(),
    )
    assert response.status_code == 200


def test_active_scim_user_requires_external_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)
    payload = _user_payload()
    payload.pop("externalId")

    response = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=payload,
    )
    assert response.status_code == 400
    assert "externalId" in response.json()["detail"]


def test_auth_and_info_expose_scim_state_without_secret(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    auth_status = client.get("/api/auth/status")
    assert auth_status.status_code == 200
    auth_body = auth_status.json()
    assert auth_body["scim_provisioning_enabled"] is True
    assert auth_body["scim_oidc_enforced"] is True

    monkeypatch.setenv("BS_API_KEY", "g" * 32)
    info = client.get(
        "/api/info",
        headers={"x-api-key": "g" * 32},
    )
    assert info.status_code == 200
    info_body = info.json()
    assert info_body["scim_provisioning_enabled"] is True
    assert info_body["scim_oidc_enforced"] is True

    assert SCIM_TOKEN not in auth_status.text
    assert SCIM_TOKEN not in info.text


def test_scim_if_match_rejects_stale_mutations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    created = client.post(
        "/api/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(),
    )
    assert created.status_code == 201
    resource = created.json()
    user_id = resource["id"]
    etag = created.headers["etag"]

    stale = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers={**_headers(), "If-Match": 'W/"stale"'},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": False}
            ],
        },
    )
    assert stale.status_code == 412
    assert stale.json()["status"] == "412"

    current = client.patch(
        f"/api/scim/v2/Users/{user_id}",
        headers={**_headers(), "If-Match": etag},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": False}
            ],
        },
    )
    assert current.status_code == 200
    new_etag = current.headers["etag"]
    assert new_etag != etag

    stale_delete = client.delete(
        f"/api/scim/v2/Users/{user_id}",
        headers={**_headers(), "If-Match": etag},
    )
    assert stale_delete.status_code == 412

    wildcard_delete = client.delete(
        f"/api/scim/v2/Users/{user_id}",
        headers={**_headers(), "If-Match": "*"},
    )
    assert wildcard_delete.status_code == 204


def test_blank_scim_store_path_uses_default(monkeypatch) -> None:
    monkeypatch.setenv("BS_SCIM_USER_STORE_PATH", "")
    from api.services.scim_directory import scim_user_store_path

    path = scim_user_store_path()
    assert path.name == "scim_users.json"
    assert ".breachscope" in path.parts
