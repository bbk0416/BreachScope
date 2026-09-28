"""SCIM 2.0 Group provisioning and BreachScope group assignments."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Mapping

from api.services.organization_scope import normalize_organization_id
from api.services.scim_directory import (
    BREACHSCOPE_GROUP_SCHEMA,
    KNOWN_ROLES,
    SCIM_GROUP_SCHEMA,
    SCIM_LIST_SCHEMA,
    SCIM_PATCH_SCHEMA,
    ScimConflictError,
    ScimDirectoryError,
    ScimFilterError,
    ScimNotFoundError,
    ScimUserDirectory,
    ScimValidationError,
    _GROUP_FILTER_RE,
    _GROUP_MEMBER_PATH_RE,
    _LOCK,
    _clean_string,
    _now_iso,
    _version_for,
    scim_group_store_path,
)


def _extract_assignment(
    payload: Mapping[str, Any],
) -> tuple[str, str]:
    extension = payload.get(BREACHSCOPE_GROUP_SCHEMA)
    if not isinstance(extension, Mapping):
        return "", ""

    role = str(extension.get("role") or "").strip().casefold()
    organization_id = str(
        extension.get("organizationId") or ""
    ).strip()

    if role and role not in KNOWN_ROLES:
        raise ScimValidationError(
            "BreachScope SCIM group role must be admin, author, reviewer, or operator."
        )
    if bool(role) != bool(organization_id):
        raise ScimValidationError(
            "BreachScope SCIM group assignment requires both role and organizationId."
        )
    if organization_id:
        try:
            organization_id = normalize_organization_id(
                organization_id,
                default=None,
            )
        except ValueError as exc:
            raise ScimValidationError(
                "BreachScope SCIM group organizationId is invalid."
            ) from exc
    return role, organization_id


def _member_ids_from_value(
    value: Any,
    *,
    valid_user_ids: set[str],
) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    member_ids: list[str] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ScimValidationError(
                "SCIM group members must be objects with a User id value."
            )
        member_id = str(item.get("value") or "").strip()
        if not member_id:
            raise ScimValidationError(
                "SCIM group member value is required."
            )
        if member_id not in valid_user_ids:
            raise ScimValidationError(
                f"SCIM group member User id does not exist: {member_id}"
            )
        if member_id not in member_ids:
            member_ids.append(member_id)
    return member_ids


def _group_from_payload(
    payload: Mapping[str, Any],
    *,
    users: list[dict[str, Any]],
    existing: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ScimValidationError(
            "SCIM Group body must be a JSON object."
        )

    display_name = _clean_string(
        payload.get("displayName"),
        field="displayName",
        required=True,
        max_length=256,
    )
    valid_user_ids = {
        str(row.get("id") or "")
        for row in users
        if str(row.get("id") or "")
    }
    member_ids = _member_ids_from_value(
        payload.get("members", []),
        valid_user_ids=valid_user_ids,
    )
    role, organization_id = _extract_assignment(payload)

    now = _now_iso()
    return {
        "id": str((existing or {}).get("id") or uuid.uuid4()),
        "displayName": display_name,
        "member_ids": member_ids,
        "role": role,
        "organization_id": organization_id,
        "created": str((existing or {}).get("created") or now),
        "last_modified": now,
    }


def public_group_resource(
    row: Mapping[str, Any],
    *,
    users: list[dict[str, Any]],
    base_url: str = "",
) -> dict[str, Any]:
    schemas = [SCIM_GROUP_SCHEMA]
    role = str(row.get("role") or "")
    organization_id = str(row.get("organization_id") or "")
    extension: dict[str, Any] = {}
    if role:
        extension["role"] = role
    if organization_id:
        extension["organizationId"] = organization_id
    if extension:
        schemas.append(BREACHSCOPE_GROUP_SCHEMA)

    users_by_id = {
        str(item.get("id") or ""): item
        for item in users
        if str(item.get("id") or "")
    }
    members: list[dict[str, Any]] = []
    for raw_member_id in row.get("member_ids") or []:
        member_id = str(raw_member_id)
        item: dict[str, Any] = {
            "value": member_id,
            "$ref": (
                f"{base_url.rstrip('/')}/Users/{member_id}"
                if base_url
                else f"/Users/{member_id}"
            ),
        }
        user = users_by_id.get(member_id)
        if user is not None:
            item["display"] = str(user.get("userName") or "")
        members.append(item)

    resource: dict[str, Any] = {
        "schemas": schemas,
        "id": str(row["id"]),
        "displayName": str(row["displayName"]),
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": str(row.get("created") or ""),
            "lastModified": str(row.get("last_modified") or ""),
            "version": _version_for(row),
            "location": (
                f"{base_url.rstrip('/')}/Groups/{row['id']}"
                if base_url
                else f"/Groups/{row['id']}"
            ),
        },
    }
    if extension:
        resource[BREACHSCOPE_GROUP_SCHEMA] = extension
    return resource


class ScimGroupDirectory:
    """JSON-backed SCIM Group directory used by OIDC identity resolution."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        user_directory: ScimUserDirectory | None = None,
    ):
        self.path = path or scim_group_store_path()
        self.user_directory = user_directory or ScimUserDirectory()

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScimDirectoryError(
                "SCIM group store is unreadable or invalid."
            ) from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get("groups"), list
        ):
            raise ScimDirectoryError(
                "SCIM group store format is invalid."
            )

        rows: list[dict[str, Any]] = []
        for row in payload["groups"]:
            if (
                isinstance(row, dict)
                and row.get("id")
                and row.get("displayName")
            ):
                rows.append(dict(row))
        return rows

    def _save(self, rows: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "groups": rows,
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

    def _users(self) -> list[dict[str, Any]]:
        return self.user_directory._load()

    @staticmethod
    def _check_uniqueness(
        rows: list[dict[str, Any]],
        candidate: Mapping[str, Any],
        *,
        exclude_id: str | None = None,
    ) -> None:
        display_name = str(
            candidate.get("displayName") or ""
        ).casefold()
        for row in rows:
            if exclude_id and str(row.get("id")) == exclude_id:
                continue
            if (
                str(row.get("displayName") or "").casefold()
                == display_name
            ):
                raise ScimConflictError(
                    "SCIM group displayName must be unique."
                )

    def all_rows(self) -> list[dict[str, Any]]:
        with _LOCK:
            return self._load()

    def list_groups(
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
            users = self._users()

        filtered = rows
        if filter_value.strip():
            match = _GROUP_FILTER_RE.fullmatch(filter_value)
            if not match:
                raise ScimFilterError(
                    'Supported SCIM Group filters are id/displayName eq "value".'
                )
            field = match.group(1)
            expected = match.group(2)
            if field.casefold() == "displayname":
                filtered = [
                    row
                    for row in rows
                    if str(
                        row.get("displayName") or ""
                    ).casefold()
                    == expected.casefold()
                ]
            else:
                filtered = [
                    row
                    for row in rows
                    if str(row.get("id") or "") == expected
                ]

        total = len(filtered)
        page = filtered[start - 1 : start - 1 + page_count]
        return {
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": len(page),
            "Resources": [
                public_group_resource(
                    row,
                    users=users,
                    base_url=base_url,
                )
                for row in page
            ],
        }

    def get_group(
        self,
        group_id: str,
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            rows = self._load()
            users = self._users()
        for row in rows:
            if str(row.get("id")) == str(group_id):
                return public_group_resource(
                    row,
                    users=users,
                    base_url=base_url,
                )
        raise ScimNotFoundError("SCIM group was not found.")

    def create_group(
        self,
        payload: Mapping[str, Any],
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            users = self._users()
            row = _group_from_payload(payload, users=users)
            rows = self._load()
            self._check_uniqueness(rows, row)
            rows.append(row)
            self._save(rows)
        return public_group_resource(
            row,
            users=users,
            base_url=base_url,
        )

    def replace_group(
        self,
        group_id: str,
        payload: Mapping[str, Any],
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        with _LOCK:
            users = self._users()
            rows = self._load()
            index = next(
                (
                    i
                    for i, row in enumerate(rows)
                    if str(row.get("id")) == str(group_id)
                ),
                None,
            )
            if index is None:
                raise ScimNotFoundError(
                    "SCIM group was not found."
                )
            row = _group_from_payload(
                payload,
                users=users,
                existing=rows[index],
            )
            self._check_uniqueness(
                rows,
                row,
                exclude_id=str(group_id),
            )
            rows[index] = row
            self._save(rows)
        return public_group_resource(
            row,
            users=users,
            base_url=base_url,
        )

    def patch_group(
        self,
        group_id: str,
        payload: Mapping[str, Any],
        *,
        base_url: str = "",
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ScimValidationError(
                "SCIM PATCH body must be a JSON object."
            )
        schemas = payload.get("schemas")
        if (
            not isinstance(schemas, list)
            or SCIM_PATCH_SCHEMA not in schemas
        ):
            raise ScimValidationError(
                "SCIM PATCH requires the PatchOp schema."
            )
        operations = payload.get("Operations")
        if not isinstance(operations, list) or not operations:
            raise ScimValidationError(
                "SCIM PATCH requires a non-empty Operations array."
            )

        with _LOCK:
            users = self._users()
            valid_user_ids = {
                str(row.get("id") or "")
                for row in users
                if str(row.get("id") or "")
            }
            rows = self._load()
            index = next(
                (
                    i
                    for i, row in enumerate(rows)
                    if str(row.get("id")) == str(group_id)
                ),
                None,
            )
            if index is None:
                raise ScimNotFoundError(
                    "SCIM group was not found."
                )

            current = dict(rows[index])
            working: dict[str, Any] = {
                "displayName": current.get("displayName"),
                "members": [
                    {"value": str(value)}
                    for value in (current.get("member_ids") or [])
                ],
                BREACHSCOPE_GROUP_SCHEMA: {
                    "role": current.get("role") or "",
                    "organizationId": (
                        current.get("organization_id") or ""
                    ),
                },
            }

            for operation in operations:
                if not isinstance(operation, Mapping):
                    raise ScimValidationError(
                        "SCIM PATCH operations must be objects."
                    )
                op = str(
                    operation.get("op") or ""
                ).strip().casefold()
                if op not in {"add", "replace", "remove"}:
                    raise ScimValidationError(
                        "SCIM PATCH op must be add, replace, or remove."
                    )
                path = str(operation.get("path") or "").strip()
                value = operation.get("value")

                if not path:
                    if op == "remove" or not isinstance(
                        value, Mapping
                    ):
                        raise ScimValidationError(
                            "Path-less SCIM PATCH operations require an object value."
                        )
                    for key, item in value.items():
                        self._apply_patch_value(
                            working,
                            str(key),
                            item,
                            op=op,
                            valid_user_ids=valid_user_ids,
                        )
                    continue

                self._apply_patch_value(
                    working,
                    path,
                    value,
                    op=op,
                    valid_user_ids=valid_user_ids,
                )

            row = _group_from_payload(
                working,
                users=users,
                existing=current,
            )
            self._check_uniqueness(
                rows,
                row,
                exclude_id=str(group_id),
            )
            rows[index] = row
            self._save(rows)

        return public_group_resource(
            row,
            users=users,
            base_url=base_url,
        )

    @staticmethod
    def _apply_patch_value(
        working: dict[str, Any],
        path: str,
        value: Any,
        *,
        op: str,
        valid_user_ids: set[str],
    ) -> None:
        normalized = path.strip()
        lowered = normalized.casefold()
        remove = op == "remove"

        member_match = _GROUP_MEMBER_PATH_RE.fullmatch(
            normalized
        )
        if member_match:
            if not remove:
                raise ScimValidationError(
                    "Filtered SCIM Group member paths only support remove.",
                    scim_type="invalidPath",
                )
            target = member_match.group(1)
            working["members"] = [
                item
                for item in (working.get("members") or [])
                if not (
                    isinstance(item, Mapping)
                    and str(item.get("value") or "") == target
                )
            ]
            return

        if lowered == "displayname":
            working["displayName"] = "" if remove else value
            return

        if lowered == "members":
            if remove:
                working["members"] = []
                return
            incoming = _member_ids_from_value(
                value,
                valid_user_ids=valid_user_ids,
            )
            if op == "replace":
                working["members"] = [
                    {"value": item}
                    for item in incoming
                ]
                return

            existing = [
                str(item.get("value") or "")
                for item in (working.get("members") or [])
                if isinstance(item, Mapping)
            ]
            for member_id in incoming:
                if member_id not in existing:
                    existing.append(member_id)
            working["members"] = [
                {"value": item}
                for item in existing
            ]
            return

        if lowered == BREACHSCOPE_GROUP_SCHEMA.casefold():
            if remove:
                working[BREACHSCOPE_GROUP_SCHEMA] = {}
                return
            if not isinstance(value, Mapping):
                raise ScimValidationError(
                    "BreachScope SCIM Group extension PATCH value must be an object."
                )
            extension = working.setdefault(
                BREACHSCOPE_GROUP_SCHEMA,
                {},
            )
            if not isinstance(extension, dict):
                extension = {}
                working[BREACHSCOPE_GROUP_SCHEMA] = extension
            for key in ("role", "organizationId"):
                if key in value:
                    extension[key] = value[key]
            return

        prefix = BREACHSCOPE_GROUP_SCHEMA.casefold() + ":"
        if lowered.startswith(prefix):
            attr = normalized[len(BREACHSCOPE_GROUP_SCHEMA) + 1 :]
            extension = working.setdefault(
                BREACHSCOPE_GROUP_SCHEMA,
                {},
            )
            if not isinstance(extension, dict):
                extension = {}
                working[BREACHSCOPE_GROUP_SCHEMA] = extension
            if attr.casefold() == "role":
                extension["role"] = "" if remove else value
                return
            if attr.casefold() == "organizationid":
                extension["organizationId"] = (
                    "" if remove else value
                )
                return

        raise ScimValidationError(
            f"Unsupported SCIM Group PATCH path: {path}",
            scim_type="invalidPath",
        )

    def delete_group(self, group_id: str) -> dict[str, Any]:
        with _LOCK:
            rows = self._load()
            index = next(
                (
                    i
                    for i, row in enumerate(rows)
                    if str(row.get("id")) == str(group_id)
                ),
                None,
            )
            if index is None:
                raise ScimNotFoundError(
                    "SCIM group was not found."
                )
            removed = rows.pop(index)
            self._save(rows)
        return dict(removed)

    def remove_user_references(self, user_id: str) -> None:
        with _LOCK:
            rows = self._load()
            changed = False
            for row in rows:
                original = [
                    str(value)
                    for value in (row.get("member_ids") or [])
                ]
                filtered = [
                    value
                    for value in original
                    if value != str(user_id)
                ]
                if filtered != original:
                    row["member_ids"] = filtered
                    row["last_modified"] = _now_iso()
                    changed = True
            if changed:
                self._save(rows)
