"""Audit trail API."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response

from api.rbac import identity_from_request
from api.services.audit_log import AuditLogService

router = APIRouter()


def _svc() -> AuditLogService:
    return AuditLogService()


@router.get("/audit", response_class=JSONResponse)
async def list_audit_events(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    action: str | None = Query(None),
    status: str | None = Query(None),
    case_id: str | None = Query(None),
):
    """Return recent audit events, newest first."""
    organization_id = identity_from_request(request).organization_id
    events = _svc().read_events(
        limit=limit,
        action=action,
        status=status,
        case_id=case_id,
        organization_id=organization_id,
    )
    return {"success": True, "events": events, "count": len(events)}


@router.get("/audit/export")
async def export_audit_events(
    request: Request,
    file_type: str = Query("jsonl", pattern="^(jsonl|csv)$"),
    limit: int = Query(1000, ge=1, le=1000),
    action: str | None = Query(None),
    status: str | None = Query(None),
    case_id: str | None = Query(None),
):
    """Export recent audit events as JSONL or CSV."""
    svc = _svc()
    organization_id = identity_from_request(request).organization_id
    events = svc.read_events(
        limit=limit,
        action=action,
        status=status,
        case_id=case_id,
        organization_id=organization_id,
    )
    if file_type == "csv":
        return Response(
            svc.export_csv(events),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=breachscope-audit.csv"},
        )
    return Response(
        svc.export_jsonl(events),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=breachscope-audit.jsonl"},
    )


@router.get("/audit/integrity", response_class=JSONResponse)
async def audit_integrity(request: Request):
    """Return a digest over audit events visible to the active organization."""
    svc = _svc()
    organization_id = identity_from_request(request).organization_id
    return {
        "success": True,
        "integrity": svc.verify_organization_integrity(
            organization_id,
        ),
    }
