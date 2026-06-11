"""Backup management API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse

from api.services.audit_log import AuditLogService
from api.services.backup_service import BackupService

router = APIRouter()


def _svc() -> BackupService:
    return BackupService()


@router.get("/backups", response_class=JSONResponse)
async def list_backups(limit: int = Query(20, ge=1, le=100)):
    """Return recent local backup archives."""
    return {"success": True, "backups": _svc().list_backups(limit=limit)}


@router.post("/backups", response_class=JSONResponse)
async def create_backup(
    request: Request,
    include_cases: bool = Query(True),
    include_audit: bool = Query(True),
    label: str | None = Query(None, max_length=120),
):
    """Create a ZIP backup containing case history, case files, and audit log."""
    backup = _svc().create_backup(include_cases=include_cases, include_audit=include_audit, label=label)
    AuditLogService().record(
        "backup.create",
        request=request,
        status="success",
        target=backup.get("filename"),
        details={"backup_id": backup.get("backup_id"), "size_bytes": backup.get("size_bytes"), "file_count": backup.get("file_count")},
    )
    return {"success": True, "backup": backup}


@router.get("/backups/{backup_id}/download")
async def download_backup(backup_id: str, request: Request):
    """Download a backup ZIP archive."""
    try:
        path = _svc().get_backup_path(backup_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="백업을 찾을 수 없습니다.")
    AuditLogService().record("backup.download", request=request, status="success", target=path.name, details={"backup_id": backup_id})
    return FileResponse(path=str(path), filename=path.name, media_type="application/zip")


@router.get("/backups/{backup_id}/integrity", response_class=JSONResponse)
async def backup_integrity(backup_id: str):
    """Return SHA-256 information for a backup archive."""
    try:
        return {"success": True, "integrity": _svc().integrity(backup_id)}
    except KeyError:
        raise HTTPException(status_code=404, detail="백업을 찾을 수 없습니다.")


@router.delete("/backups/{backup_id}", response_class=JSONResponse)
async def delete_backup(backup_id: str, request: Request):
    """Delete a local backup archive and its sidecar manifest."""
    try:
        result = _svc().delete_backup(backup_id)
    except KeyError:
        AuditLogService().record("backup.delete", request=request, status="failure", details={"backup_id": backup_id, "reason": "not_found"})
        raise HTTPException(status_code=404, detail="백업을 찾을 수 없습니다.")
    AuditLogService().record("backup.delete", request=request, status="success", target=f"{backup_id}.zip", details=result)
    return {"success": True, **result}
