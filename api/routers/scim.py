"""SCIM 2.0 provisioning endpoints."""
from __future__ import annotations

import hmac
import json
from typing import Any

from fastapi import APIRouter, Body, Query, Request
from fastapi.responses import JSONResponse, Response

from api.services.audit_log import AuditLogService
from api.services.scim_directory import (
    BREACHSCOPE_GROUP_SCHEMA,
    BREACHSCOPE_USER_SCHEMA,
    SCIM_BULK_MAX_OPERATIONS,
    SCIM_BULK_MAX_PAYLOAD_SIZE,
    SCIM_ERROR_SCHEMA,
    ScimConflictError,
    ScimDirectoryError,
    ScimFilterError,
    ScimNotFoundError,
    ScimUserDirectory,
    ScimValidationError,
    scim_bearer_token,
    scim_resource_types,
    scim_schemas,
    scim_service_provider_config,
)
from api.services.scim_bulk import ScimBulkRequestError, execute_scim_bulk
from api.services.scim_groups import ScimGroupDirectory


router = APIRouter()
SCIM_MEDIA_TYPE = "application/scim+json"


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/") + "/api/scim/v2"


def _scim_response(
    payload: dict[str, Any],
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        payload,
        status_code=status_code,
        headers=headers,
        media_type=SCIM_MEDIA_TYPE,
    )


def _scim_error(
    status_code: int,
    detail: str,
    *,
    scim_type: str | None = None,
) -> JSONResponse:
    payload: dict[str, Any] = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status_code),
        "detail": str(detail),
    }
    if scim_type:
        payload["scimType"] = scim_type
    return _scim_response(payload, status_code=status_code)


def _require_scim_bearer(request: Request) -> JSONResponse | None:
    expected = scim_bearer_token()
    if not expected:
        return _scim_error(
            503,
            "SCIM provisioning is not configured.",
        )
    auth = request.headers.get("authorization", "").strip()
    if not auth.casefold().startswith("bearer "):
        return _scim_error(401, "SCIM bearer token is required.")
    supplied = auth[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        return _scim_error(401, "SCIM bearer token is invalid.")
    return None


def _if_match_denied(
    request: Request,
    current: dict[str, Any],
) -> JSONResponse | None:
    supplied = request.headers.get("if-match", "").strip()
    if not supplied:
        return None
    expected = str((current.get("meta") or {}).get("version") or "")
    if supplied == "*" or (expected and hmac.compare_digest(supplied, expected)):
        return None
    return _scim_error(
        412,
        "SCIM resource version does not match If-Match.",
    )


def _directory_error(exc: Exception) -> JSONResponse:
    if isinstance(exc, ScimNotFoundError):
        return _scim_error(404, str(exc))
    if isinstance(exc, ScimConflictError):
        return _scim_error(
            409,
            str(exc),
            scim_type=exc.scim_type,
        )
    if isinstance(exc, ScimFilterError):
        return _scim_error(
            400,
            str(exc),
            scim_type=exc.scim_type,
        )
    if isinstance(exc, ScimValidationError):
        return _scim_error(
            400,
            str(exc),
            scim_type=exc.scim_type,
        )
    return _scim_error(500, "SCIM directory operation failed.")


def _audit_user(
    request: Request,
    action: str,
    resource: dict[str, Any],
    *,
    status: str = "success",
) -> None:
    extension = resource.get(BREACHSCOPE_USER_SCHEMA)
    organization_id = ""
    role = ""
    if isinstance(extension, dict):
        organization_id = str(extension.get("organizationId") or "")
        role = str(extension.get("role") or "")
    AuditLogService().record(
        action,
        request=request,
        status=status,
        actor="scim-provisioner",
        auth_method="scim",
        target=str(resource.get("id") or ""),
        organization_id=organization_id or None,
        details={
            "user_id": resource.get("id"),
            "user_name": resource.get("userName"),
            "external_id_present": bool(resource.get("externalId")),
            "active": resource.get("active"),
            "role": role,
        },
    )


def _audit_group(
    request: Request,
    action: str,
    resource: dict[str, Any],
) -> None:
    extension = resource.get(BREACHSCOPE_GROUP_SCHEMA)
    organization_id = ""
    role = ""
    if isinstance(extension, dict):
        organization_id = str(
            extension.get("organizationId") or ""
        )
        role = str(extension.get("role") or "")
    AuditLogService().record(
        action,
        request=request,
        status="success",
        actor="scim-provisioner",
        auth_method="scim",
        target=str(resource.get("id") or ""),
        organization_id=organization_id or None,
        details={
            "group_id": resource.get("id"),
            "display_name": resource.get("displayName"),
            "member_count": len(resource.get("members") or []),
            "role": role,
        },
    )


@router.get("/scim/v2/ServiceProviderConfig")
async def service_provider_config(request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    return _scim_response(
        scim_service_provider_config(_base_url(request))
    )


@router.get("/scim/v2/ResourceTypes")
async def resource_types(request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    return _scim_response(
        scim_resource_types(_base_url(request))
    )


@router.get("/scim/v2/ResourceTypes/User")
async def user_resource_type(request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    payload = scim_resource_types(_base_url(request))
    return _scim_response(payload["Resources"][0])


@router.get("/scim/v2/ResourceTypes/Group")
async def group_resource_type(request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    payload = scim_resource_types(_base_url(request))
    for resource in payload["Resources"]:
        if resource.get("id") == "Group":
            return _scim_response(resource)
    return _scim_error(404, "SCIM Group resource type was not found.")


@router.get("/scim/v2/Schemas")
async def schemas(request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    return _scim_response(scim_schemas(_base_url(request)))


@router.get("/scim/v2/Schemas/{schema_id:path}")
async def schema_by_id(schema_id: str, request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    payload = scim_schemas(_base_url(request))
    for resource in payload["Resources"]:
        if resource.get("id") == schema_id:
            return _scim_response(resource)
    return _scim_error(404, "SCIM schema was not found.")


@router.post("/scim/v2/Bulk")
async def bulk(request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied

    raw = await request.body()
    if len(raw) > SCIM_BULK_MAX_PAYLOAD_SIZE:
        return _scim_error(
            413,
            "The size of the bulk operation exceeds "
            f"maxPayloadSize ({SCIM_BULK_MAX_PAYLOAD_SIZE}).",
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _scim_error(
            400,
            "SCIM Bulk request body must be valid UTF-8 JSON.",
            scim_type="invalidSyntax",
        )
    if not isinstance(payload, dict):
        return _scim_error(
            400,
            "SCIM Bulk request body must be a JSON object.",
            scim_type="invalidSyntax",
        )

    try:
        response, audit_events = execute_scim_bulk(
            payload,
            base_url=_base_url(request),
            max_operations=SCIM_BULK_MAX_OPERATIONS,
        )
    except ScimBulkRequestError as exc:
        return _scim_error(
            exc.status_code,
            str(exc),
            scim_type=exc.scim_type,
        )

    for event in audit_events:
        kind = str(event.get("kind") or "")
        action = str(event.get("action") or "")
        resource = event.get("resource")
        if not action or not isinstance(resource, dict):
            continue
        if kind == "user":
            _audit_user(request, action, resource)
        elif kind == "group":
            _audit_group(request, action, resource)

    return _scim_response(response)


@router.get("/scim/v2/Users")
async def list_users(
    request: Request,
    filter: str = Query(""),
    start_index: int = Query(1, alias="startIndex", ge=1),
    count: int = Query(100, ge=0, le=200),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    try:
        payload = ScimUserDirectory().list_users(
            filter_value=filter,
            start_index=start_index,
            count=count,
            base_url=_base_url(request),
        )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    return _scim_response(payload)


@router.post("/scim/v2/Users")
async def create_user(
    request: Request,
    payload: dict[str, Any] = Body(...),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    try:
        resource = ScimUserDirectory().create_user(
            payload,
            base_url=_base_url(request),
        )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_user(request, "scim.user.create", resource)
    return _scim_response(
        resource,
        status_code=201,
        headers={
            "Location": str(resource["meta"]["location"]),
            "ETag": str(resource["meta"]["version"]),
        },
    )


@router.get("/scim/v2/Users/{user_id}")
async def get_user(user_id: str, request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    try:
        resource = ScimUserDirectory().get_user(
            user_id,
            base_url=_base_url(request),
        )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    return _scim_response(
        resource,
        headers={"ETag": str(resource["meta"]["version"])},
    )


@router.put("/scim/v2/Users/{user_id}")
async def replace_user(
    user_id: str,
    request: Request,
    payload: dict[str, Any] = Body(...),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    directory = ScimUserDirectory()
    try:
        with directory.mutation():
            current = directory.get_user(
                user_id,
                base_url=_base_url(request),
            )
            denied_version = _if_match_denied(request, current)
            if denied_version:
                return denied_version
            resource = directory.replace_user(
                user_id,
                payload,
                base_url=_base_url(request),
            )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_user(request, "scim.user.replace", resource)
    return _scim_response(
        resource,
        headers={
            "Location": str(resource["meta"]["location"]),
            "ETag": str(resource["meta"]["version"]),
        },
    )


@router.patch("/scim/v2/Users/{user_id}")
async def patch_user(
    user_id: str,
    request: Request,
    payload: dict[str, Any] = Body(...),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    directory = ScimUserDirectory()
    try:
        with directory.mutation():
            current = directory.get_user(
                user_id,
                base_url=_base_url(request),
            )
            denied_version = _if_match_denied(request, current)
            if denied_version:
                return denied_version
            resource = directory.patch_user(
                user_id,
                payload,
                base_url=_base_url(request),
            )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_user(request, "scim.user.patch", resource)
    return _scim_response(
        resource,
        headers={
            "Location": str(resource["meta"]["location"]),
            "ETag": str(resource["meta"]["version"]),
        },
    )


@router.delete("/scim/v2/Users/{user_id}")
async def delete_user(user_id: str, request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    directory = ScimUserDirectory()
    try:
        with directory.mutation():
            resource = directory.get_user(
                user_id,
                base_url=_base_url(request),
            )
            denied_version = _if_match_denied(request, resource)
            if denied_version:
                return denied_version
            directory.delete_user(user_id)
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_user(request, "scim.user.delete", resource)
    return Response(status_code=204)


@router.get("/scim/v2/Groups")
async def list_groups(
    request: Request,
    filter: str = Query(""),
    start_index: int = Query(1, alias="startIndex", ge=1),
    count: int = Query(100, ge=0, le=200),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    try:
        payload = ScimGroupDirectory().list_groups(
            filter_value=filter,
            start_index=start_index,
            count=count,
            base_url=_base_url(request),
        )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    return _scim_response(payload)


@router.post("/scim/v2/Groups")
async def create_group(
    request: Request,
    payload: dict[str, Any] = Body(...),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    try:
        resource = ScimGroupDirectory().create_group(
            payload,
            base_url=_base_url(request),
        )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_group(request, "scim.group.create", resource)
    return _scim_response(
        resource,
        status_code=201,
        headers={
            "Location": str(resource["meta"]["location"]),
            "ETag": str(resource["meta"]["version"]),
        },
    )


@router.get("/scim/v2/Groups/{group_id}")
async def get_group(group_id: str, request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    try:
        resource = ScimGroupDirectory().get_group(
            group_id,
            base_url=_base_url(request),
        )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    return _scim_response(
        resource,
        headers={"ETag": str(resource["meta"]["version"])},
    )


@router.put("/scim/v2/Groups/{group_id}")
async def replace_group(
    group_id: str,
    request: Request,
    payload: dict[str, Any] = Body(...),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    directory = ScimGroupDirectory()
    try:
        with directory.mutation():
            current = directory.get_group(
                group_id,
                base_url=_base_url(request),
            )
            denied_version = _if_match_denied(request, current)
            if denied_version:
                return denied_version
            resource = directory.replace_group(
                group_id,
                payload,
                base_url=_base_url(request),
            )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_group(request, "scim.group.replace", resource)
    return _scim_response(
        resource,
        headers={
            "Location": str(resource["meta"]["location"]),
            "ETag": str(resource["meta"]["version"]),
        },
    )


@router.patch("/scim/v2/Groups/{group_id}")
async def patch_group(
    group_id: str,
    request: Request,
    payload: dict[str, Any] = Body(...),
):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    directory = ScimGroupDirectory()
    try:
        with directory.mutation():
            current = directory.get_group(
                group_id,
                base_url=_base_url(request),
            )
            denied_version = _if_match_denied(request, current)
            if denied_version:
                return denied_version
            resource = directory.patch_group(
                group_id,
                payload,
                base_url=_base_url(request),
            )
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_group(request, "scim.group.patch", resource)
    return _scim_response(
        resource,
        headers={
            "Location": str(resource["meta"]["location"]),
            "ETag": str(resource["meta"]["version"]),
        },
    )


@router.delete("/scim/v2/Groups/{group_id}")
async def delete_group(group_id: str, request: Request):
    denied = _require_scim_bearer(request)
    if denied:
        return denied
    directory = ScimGroupDirectory()
    try:
        with directory.mutation():
            resource = directory.get_group(
                group_id,
                base_url=_base_url(request),
            )
            denied_version = _if_match_denied(request, resource)
            if denied_version:
                return denied_version
            directory.delete_group(group_id)
    except ScimDirectoryError as exc:
        return _directory_error(exc)
    _audit_group(request, "scim.group.delete", resource)
    return Response(status_code=204)
