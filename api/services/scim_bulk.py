"""SCIM 2.0 Bulk request execution for BreachScope Users and Groups."""
from __future__ import annotations

import hmac
from typing import Any, Mapping

from api.services.scim_directory import (
    SCIM_BULK_REQUEST_SCHEMA,
    SCIM_BULK_RESPONSE_SCHEMA,
    SCIM_ERROR_SCHEMA,
    ScimConflictError,
    ScimDirectoryError,
    ScimFilterError,
    ScimNotFoundError,
    ScimUserDirectory,
    ScimValidationError,
)
from api.services.scim_groups import ScimGroupDirectory


class ScimBulkRequestError(ScimDirectoryError):
    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        scim_type: str | None = None,
    ):
        super().__init__(detail)
        self.status_code = int(status_code)
        self.scim_type = scim_type


class _UnresolvedBulkReference(RuntimeError):
    def __init__(self, bulk_id: str):
        super().__init__(bulk_id)
        self.bulk_id = bulk_id


def _error_payload(
    status_code: int,
    detail: str,
    *,
    scim_type: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status_code),
        "detail": str(detail),
    }
    if scim_type:
        payload["scimType"] = scim_type
    return payload


def _exception_response(exc: Exception) -> tuple[int, dict[str, Any]]:
    if isinstance(exc, ScimNotFoundError):
        status = 404
        scim_type = None
    elif isinstance(exc, ScimConflictError):
        status = 409
        scim_type = exc.scim_type
    elif isinstance(exc, ScimFilterError):
        status = 400
        scim_type = exc.scim_type
    elif isinstance(exc, ScimValidationError):
        status = 400
        scim_type = exc.scim_type
    else:
        status = 500
        scim_type = None
    detail = (
        str(exc)
        if status != 500
        else "SCIM directory operation failed."
    )
    return status, _error_payload(
        status,
        detail,
        scim_type=scim_type,
    )


def _resolve_bulk_id(
    value: Any,
    *,
    resolved_ids: Mapping[str, str],
    declared_ids: set[str],
) -> Any:
    if not isinstance(value, str) or not value.startswith("bulkId:"):
        return value
    bulk_id = value[len("bulkId:") :]
    if not bulk_id:
        raise ScimValidationError(
            "SCIM bulkId reference is empty."
        )
    resolved = resolved_ids.get(bulk_id)
    if resolved:
        return resolved
    if bulk_id in declared_ids:
        raise _UnresolvedBulkReference(bulk_id)
    raise ScimValidationError(
        f"SCIM bulkId reference does not exist: {bulk_id}"
    )


def _resolve_member_values(
    value: Any,
    *,
    resolved_ids: Mapping[str, str],
    declared_ids: set[str],
) -> Any:
    items = value if isinstance(value, list) else [value]
    resolved_items: list[Any] = []
    for item in items:
        if not isinstance(item, Mapping):
            resolved_items.append(item)
            continue
        candidate = dict(item)
        if "value" in candidate:
            candidate["value"] = _resolve_bulk_id(
                candidate["value"],
                resolved_ids=resolved_ids,
                declared_ids=declared_ids,
            )
        resolved_items.append(candidate)
    if isinstance(value, list):
        return resolved_items
    return resolved_items[0] if resolved_items else value


def _resolve_group_member_refs(
    value: Any,
    *,
    resolved_ids: Mapping[str, str],
    declared_ids: set[str],
) -> Any:
    if isinstance(value, list):
        return [
            _resolve_group_member_refs(
                item,
                resolved_ids=resolved_ids,
                declared_ids=declared_ids,
            )
            for item in value
        ]
    if not isinstance(value, Mapping):
        return value

    result = dict(value)
    if "members" in result:
        result["members"] = _resolve_member_values(
            result["members"],
            resolved_ids=resolved_ids,
            declared_ids=declared_ids,
        )

    operations = result.get("Operations")
    if isinstance(operations, list):
        patched: list[Any] = []
        for operation in operations:
            if not isinstance(operation, Mapping):
                patched.append(operation)
                continue
            candidate = dict(operation)
            path = str(candidate.get("path") or "").strip().casefold()
            if path == "members" and "value" in candidate:
                candidate["value"] = _resolve_member_values(
                    candidate["value"],
                    resolved_ids=resolved_ids,
                    declared_ids=declared_ids,
                )
            patched.append(candidate)
        result["Operations"] = patched
    return result


def _resolved_path(
    path: str,
    *,
    resolved_ids: Mapping[str, str],
    declared_ids: set[str],
) -> str:
    parts = str(path or "").split("/")
    resolved: list[str] = []
    for part in parts:
        if part.startswith("bulkId:"):
            part = str(
                _resolve_bulk_id(
                    part,
                    resolved_ids=resolved_ids,
                    declared_ids=declared_ids,
                )
            )
        resolved.append(part)
    return "/".join(resolved)


def _resource_path(path: str) -> tuple[str, str | None]:
    candidate = str(path or "").strip()
    if candidate in {"/Users", "/Groups"}:
        return candidate[1:], None
    for kind in ("Users", "Groups"):
        prefix = f"/{kind}/"
        if candidate.startswith(prefix):
            resource_id = candidate[len(prefix) :].strip()
            if (
                resource_id
                and "/" not in resource_id
                and "?" not in resource_id
                and "#" not in resource_id
            ):
                return kind, resource_id
    raise ScimValidationError(
        "SCIM Bulk path must target /Users, /Groups, "
        "/Users/{id}, or /Groups/{id}.",
        scim_type="invalidPath",
    )


def _check_version(
    requested: object,
    resource: Mapping[str, Any],
) -> None:
    expected = str(requested or "").strip()
    if not expected or expected == "*":
        return
    current = str((resource.get("meta") or {}).get("version") or "")
    if not current or not hmac.compare_digest(expected, current):
        raise ScimBulkRequestError(
            412,
            "SCIM resource version does not match the Bulk operation version.",
        )


def _validate_request(
    payload: Mapping[str, Any],
    *,
    max_operations: int,
) -> tuple[list[dict[str, Any]], int, set[str]]:
    schemas = payload.get("schemas")
    if (
        not isinstance(schemas, list)
        or SCIM_BULK_REQUEST_SCHEMA not in schemas
    ):
        raise ScimBulkRequestError(
            400,
            "SCIM Bulk request requires the BulkRequest schema.",
            scim_type="invalidSyntax",
        )

    operations = payload.get("Operations")
    if not isinstance(operations, list) or not operations:
        raise ScimBulkRequestError(
            400,
            "SCIM Bulk request requires a non-empty Operations array.",
            scim_type="invalidSyntax",
        )
    if len(operations) > max_operations:
        raise ScimBulkRequestError(
            413,
            f"SCIM Bulk request exceeds maxOperations ({max_operations}).",
        )

    fail_on_errors = payload.get("failOnErrors", 0)
    if (
        isinstance(fail_on_errors, bool)
        or not isinstance(fail_on_errors, int)
        or fail_on_errors < 0
    ):
        raise ScimBulkRequestError(
            400,
            "SCIM Bulk failOnErrors must be a non-negative integer.",
            scim_type="invalidValue",
        )

    normalized: list[dict[str, Any]] = []
    declared_ids: set[str] = set()
    for raw in operations:
        if not isinstance(raw, Mapping):
            raise ScimBulkRequestError(
                400,
                "SCIM Bulk operations must be objects.",
                scim_type="invalidSyntax",
            )
        operation = {str(key): value for key, value in raw.items()}
        method = str(operation.get("method") or "").strip().upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ScimBulkRequestError(
                400,
                "SCIM Bulk method must be POST, PUT, PATCH, or DELETE.",
                scim_type="invalidValue",
            )
        path = str(operation.get("path") or "").strip()
        if not path:
            raise ScimBulkRequestError(
                400,
                "SCIM Bulk operation path is required.",
                scim_type="invalidPath",
            )
        bulk_id = str(operation.get("bulkId") or "").strip()
        if method == "POST":
            if not bulk_id:
                raise ScimBulkRequestError(
                    400,
                    "SCIM Bulk POST operations require bulkId.",
                    scim_type="invalidValue",
                )
            if bulk_id in declared_ids:
                raise ScimBulkRequestError(
                    400,
                    f"SCIM Bulk bulkId must be unique: {bulk_id}",
                    scim_type="uniqueness",
                )
            declared_ids.add(bulk_id)
        normalized.append(operation)

    return normalized, fail_on_errors, declared_ids


def _execute_operation(
    operation: Mapping[str, Any],
    *,
    base_url: str,
    user_directory: ScimUserDirectory,
    group_directory: ScimGroupDirectory,
    resolved_ids: dict[str, str],
    declared_ids: set[str],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    method = str(operation.get("method") or "").strip().upper()
    bulk_id = str(operation.get("bulkId") or "").strip()
    path = _resolved_path(
        str(operation.get("path") or ""),
        resolved_ids=resolved_ids,
        declared_ids=declared_ids,
    )
    kind, resource_id = _resource_path(path)

    if method == "POST" and resource_id is not None:
        raise ScimValidationError(
            "SCIM Bulk POST path must target /Users or /Groups.",
            scim_type="invalidPath",
        )
    if method != "POST" and resource_id is None:
        raise ScimValidationError(
            "SCIM Bulk PUT, PATCH, and DELETE paths must target one resource.",
            scim_type="invalidPath",
        )

    data = operation.get("data")
    if method in {"POST", "PUT", "PATCH"}:
        if not isinstance(data, Mapping):
            raise ScimValidationError(
                f"SCIM Bulk {method} operation requires object data."
            )
        if kind == "Groups":
            data = _resolve_group_member_refs(
                data,
                resolved_ids=resolved_ids,
                declared_ids=declared_ids,
            )
    elif data is not None:
        raise ScimValidationError(
            "SCIM Bulk DELETE operation must not include data."
        )

    directory = user_directory if kind == "Users" else group_directory
    audit: dict[str, Any] | None = None

    with directory.mutation():
        if method == "POST":
            if kind == "Users":
                resource = user_directory.create_user(
                    data,
                    base_url=base_url,
                )
                audit = {
                    "kind": "user",
                    "action": "scim.user.create",
                    "resource": resource,
                }
            else:
                resource = group_directory.create_group(
                    data,
                    base_url=base_url,
                )
                audit = {
                    "kind": "group",
                    "action": "scim.group.create",
                    "resource": resource,
                }
            resolved_ids[bulk_id] = str(resource["id"])
            return (
                {
                    "method": method,
                    "bulkId": bulk_id,
                    "location": str(resource["meta"]["location"]),
                    "version": str(resource["meta"]["version"]),
                    "status": "201",
                },
                audit,
            )

        assert resource_id is not None
        if kind == "Users":
            current = user_directory.get_user(
                resource_id,
                base_url=base_url,
            )
        else:
            current = group_directory.get_group(
                resource_id,
                base_url=base_url,
            )
        _check_version(operation.get("version"), current)

        if method == "DELETE":
            if kind == "Users":
                user_directory.delete_user(resource_id)
                audit = {
                    "kind": "user",
                    "action": "scim.user.delete",
                    "resource": current,
                }
            else:
                group_directory.delete_group(resource_id)
                audit = {
                    "kind": "group",
                    "action": "scim.group.delete",
                    "resource": current,
                }
            return (
                {
                    "method": method,
                    "location": str(current["meta"]["location"]),
                    "status": "204",
                },
                audit,
            )

        if method == "PUT":
            if kind == "Users":
                resource = user_directory.replace_user(
                    resource_id,
                    data,
                    base_url=base_url,
                )
                audit = {
                    "kind": "user",
                    "action": "scim.user.replace",
                    "resource": resource,
                }
            else:
                resource = group_directory.replace_group(
                    resource_id,
                    data,
                    base_url=base_url,
                )
                audit = {
                    "kind": "group",
                    "action": "scim.group.replace",
                    "resource": resource,
                }
        else:
            if kind == "Users":
                resource = user_directory.patch_user(
                    resource_id,
                    data,
                    base_url=base_url,
                )
                audit = {
                    "kind": "user",
                    "action": "scim.user.patch",
                    "resource": resource,
                }
            else:
                resource = group_directory.patch_group(
                    resource_id,
                    data,
                    base_url=base_url,
                )
                audit = {
                    "kind": "group",
                    "action": "scim.group.patch",
                    "resource": resource,
                }

        return (
            {
                "method": method,
                "location": str(resource["meta"]["location"]),
                "version": str(resource["meta"]["version"]),
                "status": "200",
            },
            audit,
        )


def execute_scim_bulk(
    payload: Mapping[str, Any],
    *,
    base_url: str,
    max_operations: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(payload, Mapping):
        raise ScimBulkRequestError(
            400,
            "SCIM Bulk request body must be a JSON object.",
            scim_type="invalidSyntax",
        )
    operations, fail_on_errors, declared_ids = _validate_request(
        payload,
        max_operations=max_operations,
    )

    user_directory = ScimUserDirectory()
    group_directory = ScimGroupDirectory(
        path=user_directory.group_path,
        user_directory=user_directory,
    )
    resolved_ids: dict[str, str] = {}
    results: dict[int, dict[str, Any]] = {}
    audit_events: list[dict[str, Any]] = []
    pending = list(range(len(operations)))
    error_count = 0

    while pending:
        progressed = False
        next_pending: list[int] = []

        for index in pending:
            if fail_on_errors and error_count >= fail_on_errors:
                break

            operation = operations[index]
            method = str(
                operation.get("method") or ""
            ).strip().upper()
            bulk_id = str(operation.get("bulkId") or "").strip()

            try:
                response, audit = _execute_operation(
                    operation,
                    base_url=base_url,
                    user_directory=user_directory,
                    group_directory=group_directory,
                    resolved_ids=resolved_ids,
                    declared_ids=declared_ids,
                )
            except _UnresolvedBulkReference:
                next_pending.append(index)
                continue
            except ScimBulkRequestError as exc:
                response = {
                    "method": method,
                    "status": str(exc.status_code),
                    "response": _error_payload(
                        exc.status_code,
                        str(exc),
                        scim_type=exc.scim_type,
                    ),
                }
                if bulk_id:
                    response["bulkId"] = bulk_id
                results[index] = response
                error_count += 1
                progressed = True
                continue
            except ScimDirectoryError as exc:
                status, error = _exception_response(exc)
                response = {
                    "method": method,
                    "status": str(status),
                    "response": error,
                }
                if bulk_id:
                    response["bulkId"] = bulk_id
                results[index] = response
                error_count += 1
                progressed = True
                continue

            results[index] = response
            if audit is not None:
                audit_events.append(audit)
            progressed = True

        if fail_on_errors and error_count >= fail_on_errors:
            break

        if not next_pending:
            break

        if progressed:
            pending = next_pending
            continue

        for index in next_pending:
            operation = operations[index]
            method = str(
                operation.get("method") or ""
            ).strip().upper()
            bulk_id = str(operation.get("bulkId") or "").strip()
            response: dict[str, Any] = {
                "method": method,
                "status": "409",
                "response": _error_payload(
                    409,
                    (
                        "SCIM Bulk operation has an unresolved "
                        "or circular bulkId dependency."
                    ),
                ),
            }
            if bulk_id:
                response["bulkId"] = bulk_id
            results[index] = response
            error_count += 1
            if fail_on_errors and error_count >= fail_on_errors:
                break
        break

    ordered_results = [
        results[index]
        for index in range(len(operations))
        if index in results
    ]
    return (
        {
            "schemas": [SCIM_BULK_RESPONSE_SCHEMA],
            "Operations": ordered_results,
        },
        audit_events,
    )
