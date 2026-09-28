from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from api.main import app
from api.rbac import identity_from_request
from api.security import (
    ApiKeyConfigurationError,
    configured_organization_api_keys,
)
from api.services.case_history import CaseHistoryService


ORG_A_KEY = "a" * 32
ORG_B_KEY = "b" * 32
GLOBAL_KEY = "g" * 32


def _report(score: int) -> dict:
    return {
        "summary": {
            "total_findings": 1,
            "risk": {"score": score, "level": "medium"},
            "host_risk_summary": [],
            "mitre_counts": {},
        }
    }


def _case(
    service: CaseHistoryService,
    root: Path,
    name: str,
    score: int,
):
    work = root / name
    (work / "out").mkdir(parents=True, exist_ok=True)
    (work / "out" / "report.json").write_text(
        json.dumps(_report(score)),
        encoding="utf-8",
    )
    return service.register_case(work, _report(score))


def _clear_auth(monkeypatch) -> None:
    for name in (
        "BS_API_KEY",
        "BS_ORGANIZATION_API_KEYS",
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
        "BS_OIDC_ISSUER_URL",
        "BS_OIDC_CLIENT_ID",
        "BS_OIDC_CLIENT_SECRET",
        "BS_OIDC_REDIRECT_URI",
        "BS_OIDC_DEFAULT_ROLE",
        "BS_OIDC_ADMIN_VALUES",
        "BS_OIDC_AUTHOR_VALUES",
        "BS_OIDC_REVIEWER_VALUES",
        "BS_OIDC_OPERATOR_VALUES",
    ):
        monkeypatch.delenv(name, raising=False)


def _configure(tmp_path: Path, monkeypatch) -> None:
    _clear_auth(monkeypatch)
    monkeypatch.setenv(
        "BS_ORGANIZATION_API_KEYS",
        json.dumps(
            {
                "org-a": ORG_A_KEY,
                "org-b": ORG_B_KEY,
            }
        ),
    )
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "history.json"),
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )


def test_organization_api_key_configuration_is_fail_closed() -> None:
    assert configured_organization_api_keys(
        {
            "BS_ORGANIZATION_API_KEYS": json.dumps(
                {"Org-A": ORG_A_KEY}
            )
        }
    ) == {"org-a": ORG_A_KEY}

    with pytest.raises(ApiKeyConfigurationError):
        configured_organization_api_keys(
            {"BS_ORGANIZATION_API_KEYS": "not-json"}
        )
    with pytest.raises(ApiKeyConfigurationError):
        configured_organization_api_keys(
            {"BS_ORGANIZATION_API_KEYS": "[]"}
        )
    with pytest.raises(ApiKeyConfigurationError):
        configured_organization_api_keys(
            {
                "BS_ORGANIZATION_API_KEYS": (
                    '{"org-a":"' + ORG_A_KEY
                    + '","org-a":"' + ORG_B_KEY + '"}'
                )
            }
        )
    with pytest.raises(ApiKeyConfigurationError):
        configured_organization_api_keys(
            {
                "BS_ORGANIZATION_API_KEYS": json.dumps(
                    {
                        "Org-A": ORG_A_KEY,
                        "org-a": ORG_B_KEY,
                    }
                )
            }
        )
    with pytest.raises(ApiKeyConfigurationError):
        configured_organization_api_keys(
            {
                "BS_ORGANIZATION_API_KEYS": json.dumps(
                    {
                        "org-a": ORG_A_KEY,
                        "org-b": ORG_A_KEY,
                    }
                )
            }
        )
    with pytest.raises(ApiKeyConfigurationError):
        configured_organization_api_keys(
            {
                "BS_API_KEY": GLOBAL_KEY,
                "BS_ORGANIZATION_API_KEYS": json.dumps(
                    {"org-a": GLOBAL_KEY}
                ),
            }
        )


def test_organization_bound_api_key_defaults_to_its_bound_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    root = tmp_path / "cases"
    a = _case(
        CaseHistoryService(organization_id="org-a"),
        root,
        "org-a",
        10,
    )
    _case(
        CaseHistoryService(organization_id="org-b"),
        root,
        "org-b",
        20,
    )

    client = TestClient(app)
    response = client.get(
        "/api/cases",
        headers={"x-api-key": ORG_A_KEY},
    )
    assert response.status_code == 200
    assert [row["case_id"] for row in response.json()["cases"]] == [
        a.case_id
    ]

    matching = client.get(
        "/api/cases",
        headers={
            "x-api-key": ORG_A_KEY,
            "x-breachscope-organization": "org-a",
        },
    )
    assert matching.status_code == 200


def test_organization_bound_api_key_cannot_switch_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    denied = client.get(
        "/api/cases",
        headers={
            "x-api-key": ORG_A_KEY,
            "x-breachscope-organization": "org-b",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "organization_scope_denied"

    invalid = client.get(
        "/api/cases",
        headers={
            "x-api-key": ORG_A_KEY,
            "x-breachscope-organization": "../escape",
        },
    )
    assert invalid.status_code == 400
    assert invalid.json()["error"] == "invalid_organization_selector"

    wrong = client.get(
        "/api/cases",
        headers={"x-api-key": "wrong-key"},
    )
    assert wrong.status_code == 401

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    denied_events = [
        row
        for row in events
        if row.get("action") == "auth.denied"
        and (row.get("details") or {}).get("reason")
        == "organization_scope_denied"
    ]
    assert denied_events
    assert denied_events[-1]["organization_id"] == "org-a"


def test_organization_bound_bearer_key_uses_bound_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    root = tmp_path / "cases"
    b = _case(
        CaseHistoryService(organization_id="org-b"),
        root,
        "org-b",
        20,
    )

    client = TestClient(app)
    response = client.get(
        "/api/cases",
        headers={"authorization": f"Bearer {ORG_B_KEY}"},
    )
    assert response.status_code == 200
    assert [row["case_id"] for row in response.json()["cases"]] == [
        b.case_id
    ]


def test_global_api_key_retains_deployment_wide_selector(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("BS_API_KEY", GLOBAL_KEY)
    root = tmp_path / "cases"
    b = _case(
        CaseHistoryService(organization_id="org-b"),
        root,
        "org-b",
        20,
    )

    client = TestClient(app)
    response = client.get(
        "/api/cases",
        headers={
            "x-api-key": GLOBAL_KEY,
            "x-breachscope-organization": "org-b",
        },
    )
    assert response.status_code == 200
    assert [row["case_id"] for row in response.json()["cases"]] == [
        b.case_id
    ]


def test_auth_status_reports_delegated_api_keys_without_secrets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    status = client.get("/api/auth/status")
    assert status.status_code == 200
    body = status.json()
    assert body["auth_required"] is True
    assert body["api_key_enabled"] is True
    assert body["global_api_key_enabled"] is False
    assert body["organization_api_key_settings_present"] is True
    assert body["organization_api_key_config_valid"] is True
    assert body["organization_api_key_count"] == 2
    assert body["active_organization_id"] == "default"
    assert body["api_key_delegated"] is None
    assert ORG_A_KEY not in status.text
    assert ORG_B_KEY not in status.text


def test_malformed_delegation_config_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("BS_ORGANIZATION_API_KEYS", "{bad-json")

    client = TestClient(app)
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    body = status.json()
    assert body["auth_required"] is True
    assert body["api_key_enabled"] is False
    assert body["organization_api_key_config_valid"] is False

    protected = client.get(
        "/api/cases",
        headers={"x-api-key": ORG_A_KEY},
    )
    assert protected.status_code == 503
    assert protected.json()["error"] == "api_key_configuration_invalid"


def test_malformed_delegation_blocks_global_api_key_too(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    monkeypatch.setenv("BS_API_KEY", GLOBAL_KEY)
    monkeypatch.setenv("BS_ORGANIZATION_API_KEYS", "{bad-json")

    client = TestClient(app)
    status = client.get("/api/auth/status").json()
    assert status["global_api_key_enabled"] is True
    assert status["api_key_enabled"] is False
    assert status["organization_api_key_config_valid"] is False

    response = client.get(
        "/api/cases",
        headers={"x-api-key": GLOBAL_KEY},
    )
    assert response.status_code == 503
    assert response.json()["error"] == "api_key_configuration_invalid"


def test_api_info_reports_organization_key_auth(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    unauthenticated = client.get("/api/info")
    assert unauthenticated.status_code == 401

    response = client.get(
        "/api/info",
        headers={"x-api-key": ORG_A_KEY},
    )
    assert response.status_code == 200
    assert response.json()["api_key_enabled"] is True
    assert ORG_A_KEY not in response.text


def test_empty_organization_api_key_map_does_not_enable_auth(
    monkeypatch,
) -> None:
    _clear_auth(monkeypatch)
    monkeypatch.setenv("BS_ORGANIZATION_API_KEYS", "{}")

    from api.security import (
        auth_is_enabled,
        organization_api_key_settings_present,
    )

    assert organization_api_key_settings_present() is False
    assert auth_is_enabled() is False


def test_auth_status_reports_bound_key_active_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)
    client = TestClient(app)

    response = client.get(
        "/api/auth/status",
        headers={"x-api-key": ORG_A_KEY},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["auth_method"] == "api_key"
    assert body["active_organization_id"] == "org-a"
    assert body["api_key_delegated"] is True


def test_web_auth_status_uses_active_organization_and_templates_match():
    source = Path("templates/web_index.html").read_text(encoding="utf-8")
    runtime = Path(
        "breachscope/runtime_data/templates/web_index.html"
    ).read_text(encoding="utf-8")

    assert source == runtime
    assert "payload.active_organization_id" in source
    assert "API key 입력 (global 또는 organization-bound)" in source


def _request_with_headers(headers: dict[str, str]) -> Request:
    raw_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in headers.items()
    ]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/cases",
            "headers": raw_headers,
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
        }
    )


def test_identity_resolver_directly_enforces_bound_key_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure(tmp_path, monkeypatch)

    identity = identity_from_request(
        _request_with_headers({"x-api-key": ORG_A_KEY})
    )
    assert identity.organization_id == "org-a"
    assert identity.role == "admin"

    with pytest.raises(HTTPException) as denied:
        identity_from_request(
            _request_with_headers(
                {
                    "x-api-key": ORG_A_KEY,
                    "x-breachscope-organization": "org-b",
                }
            )
        )
    assert denied.value.status_code == 403
