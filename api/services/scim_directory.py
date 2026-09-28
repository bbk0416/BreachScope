"""Minimal SCIM 2.0 user directory with OIDC lifecycle enforcement support."""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from api.services.organization_scope import normalize_organization_id


SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_SP_CONFIG_SCHEMA = (
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)
SCIM_RESOURCE_TYPE_SCHEMA = (
    "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
)
SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"
BREACHSCOPE_USER_SCHEMA = (
    "urn:breachscope:params:scim:schemas:extension:1.0:User"
)
KNOWN_ROLES = {"admin", "author", "reviewer", "operator"}
_LOCK = threading.RLock()
_FILTER_RE = re.compile(
    r'^\s*(userName|externalId|id)\s+eq\s+"([^"]*)"\s*$',
    re.IGNORECASE,
)


class ScimDirectoryError(RuntimeError):
    """Base class for SCIM directory errors."""


class ScimValidationError(ScimDirectoryError):
    def __init__(self, message: str, *, scim_type: str = "invalidValue"):
        super().__init__(message)
        self.scim_type = scim_type


class ScimNotFoundError(ScimDirectoryError):
    pass


class ScimConflictError(ScimDirectoryError):
    def __init__(self, message: str, *, scim_type: str = "uniqueness"):
        super().__init__(message)
        self.scim_type = scim_type


class ScimFilterError(ScimDirectoryError):
    def __init__(self, message: str, *, scim_type: str = "invalidFilter"):
        super().__init__(message)
        self.scim_type = scim_type


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def scim_bearer_token(env: Mapping[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    return str(source.get("BS_SCIM_BEARER_TOKEN", "") or "").strip()


def scim_is_configured(env: Mapping[str, str] | None = None) -> bool:
    return bool(scim_bearer_token(env))


def scim_user_store_path(
    env: Mapping[str, str] | None = None,
) -> Path:
    source = os.environ if env is None else env
    value = str(
        source.get("BS_SCIM_USER_STORE_PATH", "") or ""
    ).strip()
    if not value:
        value = "~/.breachscope/scim_users.json"
    return Path(value).expanduser()


def _version_for(row: Mapping[str, Any]) -> str:
    stable = {
        key: value
        for key, value in row.items()
        if key not in {"meta"}
    }
    digest = hashlib.sha256(
        json.dumps(
            stable,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return f'W/"{digest}"'


def _clean_string(
    value: object,
    *,
    field: str,
    required: bool = False,
    max_length: int = 512,
) -> str:
    candidate = str(value or "").strip()
    if required and not candidate:
        raise ScimValidationError(f"{field} is required.")
    if len(candidate) > max_length:
        raise ScimValidationError(
            f"{field} must be {max_length} characters or fewer."
        )
    return candidate


def _extract_role(payload: Mapping[str, Any]) -> str:
    extension = payload.get(BREACHSCOPE_USER_SCHEMA)
    if isinstance(extension, Mapping):
        raw_role = str(extension.get("role") or "").strip().casefold()
        if raw_role:
            if raw_role not in KNOWN_ROLES:
                raise ScimValidationError(
                    "BreachScope SCIM role must be admin, author, reviewer, or operator."
                )
            return raw_role

    roles = payload.get("roles")
    if roles is None:
        return ""
    if not isinstance(roles, list):
        raise ScimValidationError("SCIM roles must be an array.")
    values: list[str] = []
    for item in roles:
        if isinstance(item, Mapping):
            value = str(item.get("value") or "").strip().casefold()
        else:
            value = str(item or "").strip().casefold()
        if value:
            values.append(value)
    values = list(dict.fromkeys(values))
    if len(values) > 1:
        raise ScimValidationError(
            "BreachScope SCIM users must resolve to exactly one role."
        )
    if not values:
        return ""
    if values[0] not in KNOWN_ROLES:
        raise ScimValidationError(
            "BreachScope SCIM role must be admin, author, reviewer, or operator."
        )
    return values[0]


def _extract_organization(payload: Mapping[str, Any]) -> str:
    extension = payload.get(BREACHSCOPE_USER_SCHEMA)
    raw = ""
    if isinstance(extension, Mapping):
        raw = str(extension.get("organizationId") or "").strip()
    if not raw:
        raw = str(payload.get("organizationId") or "").strip()
    if not raw:
        return ""
    try:
        return normalize_organization_id(raw, default=None)
    except ValueError as exc:
        raise ScimValidationError(
            "BreachScope SCIM organizationId is invalid."
        ) from exc


def _resource_from_payload(
    payload: Mapping[str, Any],
    *,
    existing: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ScimValidationError("SCIM User body must be a JSON object.")

    user_name = _clean_string(
        payload.get("userName"),
        field="userName",
        required=True,
        max_length=320,
    )
    external_id = _clean_string(
        payload.get("externalId"),
        field="externalId",
        max_length=512,
    )
    active_raw = payload.get("active", True)
    if not isinstance(active_raw, bool):
        raise ScimValidationError("active must be a boolean.")
    active = bool(active_raw)
    role = _extract_role(payload)
    organization_id = _extract_organization(payload)

    if active and (not external_id or not role or not organization_id):
        raise ScimValidationError(
            "Active SCIM users require externalId, one BreachScope role, and organizationId."
        )

    now = _now_iso()
    row = {
        "id": str(
            (existing or {}).get("id")
            or uuid.uuid4()
        ),
        "userName": user_name,
        "externalId": external_id,
        "active": active,
        "role": role,
        "organization_id": organization_id,
        "created": str((existing or {}).get("created") or now),
        "last_modified": now,
    }
    return row


def _public_resource(row: Mapping[str, Any], base_url: str = "") -> dict[str, Any]:
    schemas = [SCIM_USER_SCHEMA]
    extension: dict[str, Any] = {}
    role = str(row.get("role") or "")
    organization_id = str(row.get("organization_id") or "")
    if role:
        extension["role"] = role
    if organization_id:
        extension["organizationId"] = organization_id
    if extension:
        schemas.append(BREACHSCOPE_USER_SCHEMA)

    resource: dict[str, Any] = {
        "schemas": schemas,
        "id": str(row["id"]),
        "userName": str(row["userName"]),
        "active": bool(row.get("active", False)),
        "meta": {
            "resourceType": "User",
            "created": str(row.get("created") or ""),
            "lastModified": str(row.get("last_modified") or ""),
            "version": _version_for(row),
            "location": (
                f"{base_url.rstrip('/')}/Users/{row['id']}"
                if base_url
                else f"/Users/{row['id']}"
            ),
        },
    }
    external_id = str(row.get("externalId") or "")
    if external_id:
        resource["externalId"] = external_id
    if role:
        resource["roles"] = [{"value": role, "primary": True}]
    if extension:
        resource[BREACHSCOPE_USER_SCHEMA] = extension
    return resource


class ScimUserDirectory:
    """Small JSON-backed SCIM user store with uniqueness and atomic writes."""

    def __init__(self, path: Path | None = None):
        self.path = path or scim_user_store_path()

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScimDirectoryError(
                "SCIM user store is unreadable or invalid."
            ) from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get("users"), list
        ):
            raise ScimDirectoryError("SCIM user store format is invalid.")
        rows: list[dict[str, Any]] = []
        for row in payload["users"]:
            if isinstance(row, dict) and row.get("id") and row.get("userName"):
                rows.append(dict(row))
        return rows

    def _save(self, rows: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "users": rows,
        }
        temp = self.path.with_name(
            self.path.name + f".{uuid.uuid4().hex}.tmp"
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
        os.replace(temp, self.path)

    @staticmethod
    def _check_uniqueness(
        rows: list[dict[str, Any]],
        candidate: Mapping[str, Any],
        *,
        exclude_id: str | None = None,
    ) -> None:
        user_name = str(candidate.get("userName") or "").casefold()
        external_id = str(candidate.get("externalId") or "")
        for row in rows:
            if exclude_id and str(row.get("id")) == exclude_id:
                continue
            if str(row.get("userName") or "").casefold() == user_name:
                raise ScimConflictError("SCIM userName must be unique.")
            if external_id and str(row.get("externalId") or "") == external_id:
                raise ScimConflictError("SCIM externalId must be unique.")

    def list_users(
        self,
        *,
        filter_value: str = "",
        start_index: int = 1,
        count: int = 100,
        base_url: str = "",
    ) -> dict[str, Any]:
        start = max(1, int(start_index))
        page_count = max(0, min(200, int(count)))
        with _LOCK:
            rows = self._load()

        filtered = rows
        if filter_value.strip():
            match = _FILTER_RE.fullmatch(filter_value)
            if not match:
                raise ScimFilterError(
                    'Supported SCIM filters are id/userName/externalId eq "value".'
                )
            field = match.group(1)
            expected = match.group(2)
            if field.casefold() == "username":
                filtered = [
                    row
                    for row in rows
                    if str(row.get("userName") or "").casefold()
                    == expected.casefold()
                ]
            else:
                canonical = "externalId" if field.casefold() == "externalid" else "id"
                filtered = [
                    row
                    for row in rows
                    if str(row.get(canonical) or "") == expected
                ]

        total = len(filtered)
        start_zero = start - 1
        page = filtered[start_zero : start_zero + page_count]
        return {
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": len(page),
            "Resources": [
                _public_resource(row, base_url)
                for row in page
            ],
        }

    def get_user(
        self,
        user_id: str,
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            for row in self._load():
                if str(row.get("id")) == str(user_id):
                    return _public_resource(row, base_url)
        raise ScimNotFoundError("SCIM user was not found.")

    def create_user(
        self,
        payload: Mapping[str, Any],
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        row = _resource_from_payload(payload)
        with _LOCK:
            rows = self._load()
            self._check_uniqueness(rows, row)
            rows.append(row)
            self._save(rows)
        return _public_resource(row, base_url)

    def replace_user(
        self,
        user_id: str,
        payload: Mapping[str, Any],
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            rows = self._load()
            index = next(
                (
                    i
                    for i, row in enumerate(rows)
                    if str(row.get("id")) == str(user_id)
                ),
                None,
            )
            if index is None:
                raise ScimNotFoundError("SCIM user was not found.")
            row = _resource_from_payload(
                payload,
                existing=rows[index],
            )
            self._check_uniqueness(
                rows,
                row,
                exclude_id=str(user_id),
            )
            rows[index] = row
            self._save(rows)
        return _public_resource(row, base_url)

    def patch_user(
        self,
        user_id: str,
        payload: Mapping[str, Any],
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ScimValidationError(
                "SCIM PATCH body must be a JSON object."
            )
        schemas = payload.get("schemas")
        if not isinstance(schemas, list) or SCIM_PATCH_SCHEMA not in schemas:
            raise ScimValidationError(
                "SCIM PATCH requires the PatchOp schema."
            )
        operations = payload.get("Operations")
        if not isinstance(operations, list) or not operations:
            raise ScimValidationError(
                "SCIM PATCH requires a non-empty Operations array."
            )

        with _LOCK:
            rows = self._load()
            index = next(
                (
                    i
                    for i, row in enumerate(rows)
                    if str(row.get("id")) == str(user_id)
                ),
                None,
            )
            if index is None:
                raise ScimNotFoundError("SCIM user was not found.")

            current = dict(rows[index])
            working: dict[str, Any] = {
                "userName": current.get("userName"),
                "externalId": current.get("externalId"),
                "active": bool(current.get("active", False)),
                BREACHSCOPE_USER_SCHEMA: {
                    "role": current.get("role") or "",
                    "organizationId": current.get("organization_id") or "",
                },
            }

            for operation in operations:
                if not isinstance(operation, Mapping):
                    raise ScimValidationError(
                        "SCIM PATCH operations must be objects."
                    )
                op = str(operation.get("op") or "").strip().casefold()
                if op not in {"add", "replace", "remove"}:
                    raise ScimValidationError(
                        "SCIM PATCH op must be add, replace, or remove."
                    )
                path = str(operation.get("path") or "").strip()
                value = operation.get("value")

                if not path:
                    if op == "remove" or not isinstance(value, Mapping):
                        raise ScimValidationError(
                            "Path-less SCIM PATCH operations require an object value."
                        )
                    for key, item in value.items():
                        self._apply_patch_value(
                            working,
                            str(key),
                            item,
                            remove=False,
                        )
                    continue

                self._apply_patch_value(
                    working,
                    path,
                    value,
                    remove=(op == "remove"),
                )

            row = _resource_from_payload(
                working,
                existing=current,
            )
            self._check_uniqueness(
                rows,
                row,
                exclude_id=str(user_id),
            )
            rows[index] = row
            self._save(rows)

        return _public_resource(row, base_url)

    @staticmethod
    def _apply_patch_value(
        working: dict[str, Any],
        path: str,
        value: Any,
        *,
        remove: bool,
    ) -> None:
        normalized = path.strip()
        lowered = normalized.casefold()
        if lowered == "active":
            working["active"] = False if remove else value
            return
        if lowered == "username":
            working["userName"] = "" if remove else value
            return
        if lowered == "externalid":
            working["externalId"] = "" if remove else value
            return
        if lowered == "roles":
            working["roles"] = [] if remove else value
            extension = working.setdefault(BREACHSCOPE_USER_SCHEMA, {})
            if isinstance(extension, dict):
                extension.pop("role", None)
            return

        if lowered == BREACHSCOPE_USER_SCHEMA.casefold():
            if remove:
                working[BREACHSCOPE_USER_SCHEMA] = {}
                working.pop("roles", None)
                return
            if not isinstance(value, Mapping):
                raise ScimValidationError(
                    "BreachScope SCIM extension PATCH value must be an object."
                )
            extension = working.setdefault(
                BREACHSCOPE_USER_SCHEMA,
                {},
            )
            if not isinstance(extension, dict):
                extension = {}
                working[BREACHSCOPE_USER_SCHEMA] = extension
            for key in ("role", "organizationId"):
                if key in value:
                    extension[key] = value[key]
            if "role" in value:
                working.pop("roles", None)
            return

        prefix = BREACHSCOPE_USER_SCHEMA.casefold() + ":"
        if lowered.startswith(prefix):
            attr = normalized[len(BREACHSCOPE_USER_SCHEMA) + 1 :]
            extension = working.setdefault(BREACHSCOPE_USER_SCHEMA, {})
            if not isinstance(extension, dict):
                extension = {}
                working[BREACHSCOPE_USER_SCHEMA] = extension
            if attr.casefold() == "role":
                extension["role"] = "" if remove else value
                working.pop("roles", None)
                return
            if attr.casefold() == "organizationid":
                extension["organizationId"] = "" if remove else value
                return

        raise ScimValidationError(
            f"Unsupported SCIM PATCH path: {path}",
            scim_type="invalidPath",
        )

    def delete_user(self, user_id: str) -> dict[str, Any]:
        with _LOCK:
            rows = self._load()
            index = next(
                (
                    i
                    for i, row in enumerate(rows)
                    if str(row.get("id")) == str(user_id)
                ),
                None,
            )
            if index is None:
                raise ScimNotFoundError("SCIM user was not found.")
            removed = rows.pop(index)
            self._save(rows)
        return dict(removed)

    def find_by_oidc_subject(
        self,
        subject: str,
    ) -> dict[str, Any] | None:
        candidate = str(subject or "")
        if not candidate:
            return None
        with _LOCK:
            for row in self._load():
                if str(row.get("externalId") or "") == candidate:
                    return dict(row)
        return None

    def stats(self) -> dict[str, int]:
        with _LOCK:
            rows = self._load()
        return {
            "total_users": len(rows),
            "active_users": sum(
                1 for row in rows
                if bool(row.get("active", False))
            ),
        }

    def active_roles(self) -> list[str]:
        roles: set[str] = set()
        with _LOCK:
            for row in self._load():
                if not bool(row.get("active", False)):
                    continue
                role = str(row.get("role") or "").strip().casefold()
                if role in KNOWN_ROLES:
                    roles.add(role)
        return sorted(roles)

    def oidc_identity(
        self,
        subject: str,
    ) -> tuple[str, str] | None:
        row = self.find_by_oidc_subject(subject)
        if not row or not bool(row.get("active", False)):
            return None
        role = str(row.get("role") or "").strip().casefold()
        organization_id = str(row.get("organization_id") or "").strip()
        if role not in KNOWN_ROLES or not organization_id:
            return None
        try:
            organization_id = normalize_organization_id(
                organization_id,
                default=None,
            )
        except ValueError:
            return None
        return role, organization_id


def scim_service_provider_config(base_url: str) -> dict[str, Any]:
    return {
        "schemas": [SCIM_SP_CONFIG_SCHEMA],
        "documentationUri": "",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer Token",
                "description": "Dedicated BS_SCIM_BEARER_TOKEN",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{base_url.rstrip('/')}/ServiceProviderConfig",
        },
    }


def scim_resource_types(base_url: str) -> dict[str, Any]:
    resource = {
        "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "schema": SCIM_USER_SCHEMA,
        "schemaExtensions": [
            {
                "schema": BREACHSCOPE_USER_SCHEMA,
                "required": False,
            }
        ],
        "meta": {
            "resourceType": "ResourceType",
            "location": f"{base_url.rstrip('/')}/ResourceTypes/User",
        },
    }
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [resource],
    }


def scim_schemas(base_url: str) -> dict[str, Any]:
    core = {
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": SCIM_USER_SCHEMA,
        "name": "User",
        "description": "SCIM core User subset supported by BreachScope.",
        "attributes": [
            {
                "name": "userName",
                "type": "string",
                "multiValued": False,
                "required": True,
                "caseExact": False,
                "uniqueness": "server",
            },
            {
                "name": "externalId",
                "type": "string",
                "multiValued": False,
                "required": False,
                "caseExact": True,
                "uniqueness": "server",
            },
            {
                "name": "active",
                "type": "boolean",
                "multiValued": False,
                "required": False,
            },
            {
                "name": "roles",
                "type": "complex",
                "multiValued": True,
                "required": False,
                "subAttributes": [
                    {"name": "value", "type": "string"},
                    {"name": "primary", "type": "boolean"},
                ],
            },
        ],
        "meta": {
            "resourceType": "Schema",
            "location": f"{base_url.rstrip('/')}/Schemas/{SCIM_USER_SCHEMA}",
        },
    }
    extension = {
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": BREACHSCOPE_USER_SCHEMA,
        "name": "BreachScopeUser",
        "description": "BreachScope organization and role assignment.",
        "attributes": [
            {
                "name": "organizationId",
                "type": "string",
                "multiValued": False,
                "required": False,
            },
            {
                "name": "role",
                "type": "string",
                "multiValued": False,
                "required": False,
                "canonicalValues": sorted(KNOWN_ROLES),
            },
        ],
        "meta": {
            "resourceType": "Schema",
            "location": f"{base_url.rstrip('/')}/Schemas/{BREACHSCOPE_USER_SCHEMA}",
        },
    }
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 2,
        "startIndex": 1,
        "itemsPerPage": 2,
        "Resources": [core, extension],
    }
