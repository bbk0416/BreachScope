"""분석 케이스 이력 API."""
from __future__ import annotations

from pathlib import Path
from functools import wraps
import threading
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from api.services.case_history import CaseHistoryService
from api.services.artifact_encryption import (
    ArtifactEncryptionError,
    artifact_exists,
    encrypted_path,
    iter_artifact_chunks,
    verify_artifact,
)
from api.services.audit_log import AuditLogService, actor_from_request
from api.services.report_preview import load_preview
from api.services.object_storage import (
    ObjectStorageError,
    ObjectStorageService,
)
from api.rbac import (
    PERMISSION_CASE_OBJECT_STORAGE,
    ROLE_OPERATOR,
    identity_from_request,
    require_roles,
)

router = APIRouter()

_OBJECT_STORAGE_LOCKS_GUARD = threading.Lock()
_OBJECT_STORAGE_LOCKS: dict[str, threading.Lock] = {}


def _object_storage_operation_locked(func):
    """Serialize object-storage operations for the same case in this process."""

    @wraps(func)
    def wrapped(case_id: str, *args, **kwargs):
        key = str(case_id or "")
        with _OBJECT_STORAGE_LOCKS_GUARD:
            lock = _OBJECT_STORAGE_LOCKS.get(key)
            if lock is None:
                lock = threading.Lock()
                _OBJECT_STORAGE_LOCKS[key] = lock
        with lock:
            return func(case_id, *args, **kwargs)

    return wrapped


class CaseWorkflowUpdate(BaseModel):
    """Analyst-owned case workflow fields.

    Generated evidence fields are deliberately excluded so a triage update cannot
    alter the analysis result, artifacts, or report hashes.
    """

    workflow_status: str | None = Field(None, description="new, triage, investigating, contained, resolved, false_positive")
    assignee: str | None = Field(None, max_length=120)
    tags: list[str] | str | None = None
    notes: str | None = Field(None, max_length=8000)
    severity_override: str | None = Field(None, description="none, low, medium, high, critical")
    closure_summary: str | None = Field(None, max_length=4000)
    title: str | None = Field(None, max_length=180)


def _service(request: Request) -> CaseHistoryService:
    return CaseHistoryService(
        organization_id=identity_from_request(request).organization_id
    )


def _object_storage_service() -> ObjectStorageService:
    return ObjectStorageService()


@router.get("/cases", response_class=JSONResponse)
async def list_cases(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
):
    """최근 분석 케이스 목록을 반환합니다."""
    return {"success": True, "cases": _service(request).list_cases(limit=limit)}


@router.post("/cases/prune", response_class=JSONResponse)
async def prune_cases(
    request: Request,
    keep_last: int = Query(50, ge=0, le=1000),
    older_than_days: int | None = Query(None, ge=0, le=3650),
    dry_run: bool = Query(True),
    remove_files: bool = Query(True),
):
    """오래된 케이스를 정리합니다. 기본은 dry-run으로 후보만 반환합니다."""
    result = _service(request).prune_cases(
        keep_last=keep_last,
        older_than_days=older_than_days,
        dry_run=dry_run,
        remove_files=remove_files,
    )
    AuditLogService().record(
        "case.prune",
        request=request,
        status="success",
        details={
            "keep_last": keep_last,
            "older_than_days": older_than_days,
            "dry_run": dry_run,
            "candidate_count": result.get("candidate_count"),
            "removed_case_records": result.get("removed_case_records"),
            "removed_files": result.get("removed_files"),
            "failed_file_deletions": result.get("failed_file_deletions"),
            "blocked_remote_replicas": result.get("blocked_remote_replicas"),
        },
    )
    return {"success": True, **result}


@router.get("/cases/workflow/summary", response_class=JSONResponse)
async def workflow_summary(request: Request):
    """케이스 워크플로 보드 요약을 반환합니다."""
    return {"success": True, "summary": _service(request).workflow_summary()}


@router.patch("/cases/{case_id}/workflow", response_class=JSONResponse)
async def update_case_workflow(case_id: str, payload: CaseWorkflowUpdate, request: Request):
    """케이스 담당자/상태/태그/분석 메모를 수정합니다."""
    actor = actor_from_request(request)
    try:
        updated = _service(request).update_case_workflow(
            case_id,
            workflow_status=payload.workflow_status,
            assignee=payload.assignee,
            tags=payload.tags,
            notes=payload.notes,
            severity_override=payload.severity_override,
            closure_summary=payload.closure_summary,
            title=payload.title,
            updated_by=actor.subject,
        )
    except KeyError:
        AuditLogService().record("case.workflow.update", request=request, status="failure", case_id=case_id, details={"reason": "not_found"})
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")
    except ValueError as exc:
        AuditLogService().record("case.workflow.update", request=request, status="failure", case_id=case_id, details={"reason": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))

    AuditLogService().record(
        "case.workflow.update",
        request=request,
        status="success",
        case_id=case_id,
        details={
            "workflow_status": updated.get("workflow_status"),
            "assignee": updated.get("assignee"),
            "tags": updated.get("tags"),
            "severity_override": updated.get("severity_override"),
        },
    )
    return {"success": True, "case": updated}

@router.get("/cases/{case_id}", response_class=JSONResponse)
def get_case(case_id: str, request: Request):
    """단일 케이스 메타데이터와 대시보드 미리보기를 반환합니다."""
    identity = identity_from_request(request)
    try:
        case = _service(request).get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    preview = None
    preview_source: str | None = None
    if case.get("exists"):
        try:
            preview = load_preview(case["work_dir"])
            preview_source = "local"
        except FileNotFoundError:
            preview = None
        except ArtifactEncryptionError as exc:
            raise HTTPException(
                status_code=503,
                detail="암호화된 케이스를 현재 키로 복호화할 수 없습니다.",
            ) from exc
    else:
        remote = dict(case.get("object_storage") or {})
        if remote:
            try:
                storage = _object_storage_service()
                with storage.temporary_case(
                    case_id,
                    remote,
                    organization_id=identity.organization_id,
                ) as (remote_work_dir, restored):
                    try:
                        preview = load_preview(remote_work_dir)
                        preview_source = "object_storage"
                    except FileNotFoundError:
                        preview = None
                    remote_file_count = int(
                        restored.get("file_count") or 0
                    )
            except (ObjectStorageError, ArtifactEncryptionError) as exc:
                AuditLogService().record(
                    "case.view",
                    request=request,
                    status="failure",
                    case_id=case_id,
                    details={
                        "reason": str(exc),
                        "source": "object_storage",
                    },
                )
                raise HTTPException(
                    status_code=503,
                    detail="원격 보관 케이스를 검증해 읽을 수 없습니다.",
                ) from exc
            AuditLogService().record(
                "case.object_storage.read",
                request=request,
                status="success",
                case_id=case_id,
                details={
                    "mode": "preview",
                    "file_count": remote_file_count,
                },
            )

    AuditLogService().record(
        "case.view",
        request=request,
        status="success",
        case_id=case_id,
        details={
            "exists": case.get("exists"),
            "preview_source": preview_source,
        },
    )
    return {
        "success": True,
        "case": case,
        "preview": preview,
        "preview_source": preview_source,
    }


@router.get("/cases/{case_id}/report")
def get_case_report(
    case_id: str,
    request: Request,
    file_type: str = Query("html", pattern="^(html|json|csv|iocs|rules|pdf|manifest|zip)$"),
):
    """케이스 ID 기준으로 산출물을 다운로드합니다. 파일 시스템 경로를 URL에 노출하지 않습니다."""
    identity = identity_from_request(request)
    try:
        case = _service(request).get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    suffix_map = {
        "html": ".html",
        "json": ".json",
        "csv": ".csv",
        "iocs": ".iocs.csv",
        "rules": ".rules.csv",
        "pdf": ".pdf",
        "manifest": ".manifest.json",
        "zip": ".zip",
    }
    media_map = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "iocs": "text/csv",
        "rules": "text/csv",
        "pdf": "application/pdf",
        "manifest": "application/json",
        "zip": "application/zip",
    }

    from api.services.path_boundary import (
        WorkDirBoundaryError,
        validate_managed_work_dir,
    )

    work_path: Path | None = None
    artifact_source = "local"
    storage: ObjectStorageService | None = None
    temporary_path: Path | None = None
    remote_restore: dict[str, Any] | None = None

    if case.get("exists"):
        try:
            work_path = validate_managed_work_dir(
                str(case.get("work_dir") or ""),
                allow_temp=True,
                must_exist=True,
            )
        except (WorkDirBoundaryError, FileNotFoundError):
            raise HTTPException(
                status_code=404,
                detail="케이스 작업 디렉토리를 찾을 수 없습니다.",
            )
    else:
        remote = dict(case.get("object_storage") or {})
        if not remote:
            raise HTTPException(
                status_code=404,
                detail="케이스 작업 디렉토리를 찾을 수 없습니다.",
            )
        try:
            storage = _object_storage_service()
            temporary_path, remote_restore = (
                storage.materialize_temporary_case(
                    case_id,
                    remote,
                    organization_id=identity.organization_id,
                )
            )
            work_path = temporary_path
            artifact_source = "object_storage"
        except (ObjectStorageError, ArtifactEncryptionError) as exc:
            AuditLogService().record(
                "case.download",
                request=request,
                status="failure",
                case_id=case_id,
                details={
                    "file_type": file_type,
                    "reason": str(exc),
                    "source": "object_storage",
                },
            )
            raise HTTPException(
                status_code=503,
                detail="원격 보관 케이스를 검증해 읽을 수 없습니다.",
            ) from exc

    assert work_path is not None
    report_prefix = work_path / "out" / "report"
    file_path = report_prefix.with_suffix(suffix_map[file_type])

    if not artifact_exists(file_path):
        if storage is not None and temporary_path is not None:
            storage.cleanup_temporary_case(temporary_path)
        raise HTTPException(
            status_code=404,
            detail=f"{file_type.upper()} 산출물을 찾을 수 없습니다.",
        )

    if file_path.exists():
        background = None
        if storage is not None and temporary_path is not None:
            background = BackgroundTask(
                storage.cleanup_temporary_case,
                temporary_path,
            )
        AuditLogService().record(
            "case.download",
            request=request,
            status="success",
            case_id=case_id,
            target=file_path.name,
            details={
                "file_type": file_type,
                "encrypted_at_rest": False,
                "source": artifact_source,
            },
        )
        return FileResponse(
            path=str(file_path),
            filename=file_path.name,
            media_type=media_map[file_type],
            background=background,
        )

    try:
        verify_artifact(file_path, work_path)
    except ArtifactEncryptionError as exc:
        if storage is not None and temporary_path is not None:
            storage.cleanup_temporary_case(temporary_path)
        AuditLogService().record(
            "case.download",
            request=request,
            status="failure",
            case_id=case_id,
            target=encrypted_path(file_path).name,
            details={
                "file_type": file_type,
                "reason": "decrypt_failed",
                "source": artifact_source,
            },
        )
        raise HTTPException(
            status_code=503,
            detail="암호화된 산출물을 현재 키로 복호화할 수 없습니다.",
        ) from exc

    AuditLogService().record(
        "case.download",
        request=request,
        status="success",
        case_id=case_id,
        target=file_path.name,
        details={
            "file_type": file_type,
            "encrypted_at_rest": True,
            "source": artifact_source,
            "remote_file_count": (
                int(remote_restore.get("file_count") or 0)
                if remote_restore is not None
                else None
            ),
        },
    )
    if artifact_source == "object_storage":
        AuditLogService().record(
            "case.object_storage.read",
            request=request,
            status="success",
            case_id=case_id,
            details={
                "mode": "report",
                "file_type": file_type,
            },
        )

    background = None
    stream = iter_artifact_chunks(file_path, work_path)
    if storage is not None and temporary_path is not None:
        cleanup_storage = storage
        cleanup_path = temporary_path
        source_stream = stream

        def remote_stream():
            try:
                yield from source_stream
            finally:
                cleanup_storage.cleanup_temporary_case(cleanup_path)

        stream = remote_stream()
        background = BackgroundTask(
            cleanup_storage.cleanup_temporary_case,
            cleanup_path,
        )

    return StreamingResponse(
        stream,
        media_type=media_map[file_type],
        headers={
            "Content-Disposition": f'attachment; filename="{file_path.name}"',
            "X-BreachScope-Artifact-Source": artifact_source,
        },
        background=background,
    )


@router.post(
    "/cases/{case_id}/object-storage/replicate",
    response_class=JSONResponse,
)
@_object_storage_operation_locked
def replicate_case_to_object_storage(
    case_id: str,
    request: Request,
):
    identity = require_roles(
        request,
        ROLE_OPERATOR,
        permission=PERMISSION_CASE_OBJECT_STORAGE,
    )
    try:
        case = _service(request).get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    if not case.get("exists"):
        raise HTTPException(
            status_code=409,
            detail="원격 복제를 위해 로컬 케이스 디렉토리가 필요합니다.",
        )
    if case.get("object_storage"):
        raise HTTPException(
            status_code=409,
            detail="이미 원격 replica가 있습니다. 기존 replica를 먼저 삭제하세요.",
        )

    storage = _object_storage_service()
    try:
        remote = storage.replicate_case(
            case_id,
            str(case.get("work_dir") or ""),
            organization_id=identity.organization_id,
        )
    except ObjectStorageError as exc:
        AuditLogService().record(
            "case.object_storage.replicate",
            request=request,
            status="failure",
            case_id=case_id,
            details={"reason": str(exc), "stage": "upload"},
        )
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        updated = _service(request).set_object_storage_state(
            case_id,
            remote,
            updated_by=identity.subject,
        )
    except Exception as exc:
        rollback_error = None
        try:
            storage.delete_replica(
                case_id,
                remote,
                organization_id=identity.organization_id,
            )
        except Exception as cleanup_exc:
            rollback_error = str(cleanup_exc)
        AuditLogService().record(
            "case.object_storage.replicate",
            request=request,
            status="failure",
            case_id=case_id,
            details={
                "reason": "case_index_persist_failed",
                "rollback_error": rollback_error,
            },
        )
        detail = (
            "원격 복제 metadata 저장에 실패해 업로드를 되돌렸습니다."
            if rollback_error is None
            else "원격 복제 metadata 저장과 원격 rollback이 모두 실패했습니다. 운영자 확인이 필요합니다."
        )
        raise HTTPException(status_code=500, detail=detail) from exc

    AuditLogService().record(
        "case.object_storage.replicate",
        request=request,
        status="success",
        case_id=case_id,
        details={
            "provider": remote.get("provider"),
            "bucket": remote.get("bucket"),
            "case_prefix": remote.get("case_prefix"),
            "file_count": remote.get("file_count"),
            "total_bytes": remote.get("total_bytes"),
        },
    )
    return {
        "success": True,
        "object_storage": updated.get("object_storage"),
    }


@router.post(
    "/cases/{case_id}/object-storage/archive",
    response_class=JSONResponse,
)
@_object_storage_operation_locked
def archive_case_to_object_storage(
    case_id: str,
    request: Request,
):
    identity = require_roles(
        request,
        ROLE_OPERATOR,
        permission=PERMISSION_CASE_OBJECT_STORAGE,
    )
    try:
        case = _service(request).get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    remote = dict(case.get("object_storage") or {})
    if not remote:
        raise HTTPException(
            status_code=409,
            detail="원격 archive를 위해 먼저 원격 replica를 생성해야 합니다.",
        )
    if not case.get("exists"):
        raise HTTPException(
            status_code=409,
            detail="로컬 케이스 파일이 이미 없습니다.",
        )

    storage = _object_storage_service()
    try:
        verification = storage.verify_replica(
            case_id,
            remote,
            organization_id=identity.organization_id,
        )
    except ObjectStorageError as exc:
        AuditLogService().record(
            "case.object_storage.archive",
            request=request,
            status="failure",
            case_id=case_id,
            details={"reason": str(exc), "stage": "remote_verify"},
        )
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if not verification.get("verified"):
        AuditLogService().record(
            "case.object_storage.archive",
            request=request,
            status="failure",
            case_id=case_id,
            details={
                "reason": "remote_replica_not_verified",
                "stage": "remote_verify",
            },
        )
        raise HTTPException(
            status_code=503,
            detail="원격 replica 복원 검증에 실패했습니다.",
        )

    result = _service(request).archive_local_case(
        case_id,
        expected_manifest_sha256=str(
            verification.get("manifest_sha256") or ""
        ),
    )
    if not result.get("archived"):
        reason = str(result.get("reason") or "archive_failed")
        AuditLogService().record(
            "case.object_storage.archive",
            request=request,
            status="failure",
            case_id=case_id,
            details={
                "reason": reason,
                "stage": "local_remove",
                "remote_verified": True,
            },
        )
        status_code = 500 if reason == "file_removal_failed" else 409
        raise HTTPException(
            status_code=status_code,
            detail=f"로컬 archive 실패: {reason}",
        )

    AuditLogService().record(
        "case.object_storage.archive",
        request=request,
        status="success",
        case_id=case_id,
        details={
            "provider": verification.get("provider"),
            "bucket": verification.get("bucket"),
            "case_prefix": verification.get("case_prefix"),
            "manifest_sha256": verification.get("manifest_sha256"),
            "verified_at": verification.get("verified_at"),
            "file_count": verification.get("file_count"),
            "removed_files": result.get("removed_files"),
        },
    )
    return {
        "success": True,
        "archive": {
            **result,
            "verification": verification,
        },
    }


@router.post(
    "/cases/{case_id}/object-storage/restore",
    response_class=JSONResponse,
)
@_object_storage_operation_locked
def restore_case_from_object_storage(
    case_id: str,
    request: Request,
    overwrite: bool = Query(False),
):
    identity = require_roles(
        request,
        ROLE_OPERATOR,
        permission=PERMISSION_CASE_OBJECT_STORAGE,
    )
    try:
        case = _service(request).get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    remote = dict(case.get("object_storage") or {})
    if not remote:
        raise HTTPException(
            status_code=409,
            detail="이 케이스에는 원격 replica 메타데이터가 없습니다.",
        )

    work_dir = Path(str(case.get("work_dir") or ""))
    if work_dir.exists() and any(work_dir.iterdir()) and not overwrite:
        raise HTTPException(
            status_code=409,
            detail="로컬 케이스가 이미 존재합니다. overwrite=true가 필요합니다.",
        )

    try:
        result = _object_storage_service().restore_case(
            case_id,
            str(case.get("work_dir") or ""),
            remote,
            overwrite=overwrite,
            organization_id=identity.organization_id,
        )
        _service(request).mark_object_storage_restored(
            case_id,
            restored_at=str(result.get("restored_at") or ""),
            restored_by=identity.subject,
        )
    except ObjectStorageError as exc:
        AuditLogService().record(
            "case.object_storage.restore",
            request=request,
            status="failure",
            case_id=case_id,
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    AuditLogService().record(
        "case.object_storage.restore",
        request=request,
        status="success",
        case_id=case_id,
        details={
            "file_count": result.get("file_count"),
            "verified": result.get("verified"),
        },
    )
    return {"success": True, "restore": result}


@router.delete(
    "/cases/{case_id}/object-storage",
    response_class=JSONResponse,
)
@_object_storage_operation_locked
def delete_case_object_storage_replica(
    case_id: str,
    request: Request,
    forget: bool = Query(False),
):
    identity = require_roles(
        request,
        ROLE_OPERATOR,
        permission=PERMISSION_CASE_OBJECT_STORAGE,
    )
    try:
        case = _service(request).get_case(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    remote = dict(case.get("object_storage") or {})
    if not remote:
        raise HTTPException(
            status_code=404,
            detail="원격 replica 메타데이터가 없습니다.",
        )

    if forget:
        _service(request).clear_object_storage_state(case_id)
        result = {
            "forgotten": True,
            "remote_deleted": False,
            "forgotten_by": identity.subject,
        }
        AuditLogService().record(
            "case.object_storage.forget",
            request=request,
            status="success",
            case_id=case_id,
            details=result,
        )
        return {"success": True, "delete": result}

    try:
        result = _object_storage_service().delete_replica(
            case_id,
            remote,
            organization_id=identity.organization_id,
        )
        _service(request).clear_object_storage_state(case_id)
    except ObjectStorageError as exc:
        AuditLogService().record(
            "case.object_storage.delete",
            request=request,
            status="failure",
            case_id=case_id,
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    AuditLogService().record(
        "case.object_storage.delete",
        request=request,
        status="success",
        case_id=case_id,
        details={
            "deleted_object_count": result.get("deleted_object_count"),
        },
    )
    return {"success": True, "delete": result}


@router.delete("/cases/{case_id}", response_class=JSONResponse)
async def delete_case(case_id: str, request: Request, remove_files: bool = Query(True)):
    """케이스 이력에서 제거합니다. 안전한 작업 디렉토리만 파일까지 삭제합니다."""
    try:
        result = _service(request).delete_case(case_id, remove_files=remove_files)
    except KeyError:
        AuditLogService().record("case.delete", request=request, status="failure", case_id=case_id, details={"reason": "not_found"})
        raise HTTPException(status_code=404, detail="케이스를 찾을 수 없습니다.")

    if not result.get("deleted"):
        AuditLogService().record("case.delete", request=request, status="failure", case_id=case_id, details=result)
        detail = (
            "원격 replica가 있습니다. 원격 replica를 먼저 삭제하거나 forget=true로 메타데이터를 정리하세요."
            if result.get("reason") == "remote_replica_exists"
            else "케이스 파일 삭제를 완료하지 못해 이력을 유지했습니다."
        )
        raise HTTPException(
            status_code=409,
            detail=detail,
        )

    AuditLogService().record("case.delete", request=request, status="success", case_id=case_id, details=result)
    return {"success": True, **result}

# BREACHSCOPE_P2_08J_CASE_DELETE_OUTCOME_CONSISTENCY_V1
