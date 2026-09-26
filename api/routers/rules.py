"""규칙 및 룰 튜닝 프로필 API."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api.services.audit_log import AuditLogService, actor_from_request
from api.services.rule_tuning import (
    RuleTuningProfileError,
    RuleTuningProfileService,
    RuleTuningVersionConflict,
)
from breachscope.rules import load_rules
from breachscope.runtime_paths import default_rules_dir


logger = logging.getLogger(__name__)
router = APIRouter()


class RuleTuningProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field("", max_length=1000)
    rule_include: list[str] | str | None = None
    rule_exclude: list[str] | str | None = None


class RuleTuningProfileUpdate(RuleTuningProfileCreate):
    expected_version: int = Field(..., ge=1)


def _profile_service() -> RuleTuningProfileService:
    return RuleTuningProfileService()


@router.get("/rules", response_class=JSONResponse)
async def get_rules():
    """사용 가능한 탐지 규칙 목록 조회."""
    try:
        rules_dir = default_rules_dir()
        if not rules_dir.exists():
            raise HTTPException(status_code=404, detail="규칙 디렉토리를 찾을 수 없습니다.")

        rules = load_rules(rules_dir)
        rules_list = [
            {
                "id": rule.id,
                "title": rule.name,
                "severity": rule.severity,
                "mitre_technique": rule.mitre_technique,
                "field": rule.field,
                "pattern": rule.pattern,
            }
            for rule in rules
        ]
        return {"success": True, "count": len(rules_list), "rules": rules_list}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("규칙 로드 실패: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="규칙 로드 실패") from exc


@router.get("/rules/profiles", response_class=JSONResponse)
async def list_rule_tuning_profiles():
    try:
        return {"success": True, "profiles": _profile_service().list_profiles()}
    except RuleTuningProfileError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/rules/profiles/{profile_id}", response_class=JSONResponse)
async def get_rule_tuning_profile(profile_id: str):
    try:
        return {"success": True, "profile": _profile_service().get_profile(profile_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="룰 튜닝 프로필을 찾을 수 없습니다.") from exc
    except RuleTuningProfileError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/rules/profiles", response_class=JSONResponse)
async def create_rule_tuning_profile(payload: RuleTuningProfileCreate, request: Request):
    actor = actor_from_request(request)
    try:
        profile = _profile_service().create_profile(
            name=payload.name,
            description=payload.description,
            rule_include=payload.rule_include,
            rule_exclude=payload.rule_exclude,
            updated_by=actor.subject,
        )
    except RuleTuningProfileError as exc:
        AuditLogService().record(
            "rule.profile.create",
            request=request,
            status="failure",
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditLogService().record(
        "rule.profile.create",
        request=request,
        status="success",
        target=profile["profile_id"],
        details={
            "version": profile["version"],
            "name": profile["name"],
            "rule_include": profile["rule_include"],
            "rule_exclude": profile["rule_exclude"],
        },
    )
    return {"success": True, "profile": profile}


@router.put("/rules/profiles/{profile_id}", response_class=JSONResponse)
async def update_rule_tuning_profile(
    profile_id: str,
    payload: RuleTuningProfileUpdate,
    request: Request,
):
    actor = actor_from_request(request)
    try:
        profile = _profile_service().update_profile(
            profile_id,
            expected_version=payload.expected_version,
            name=payload.name,
            description=payload.description,
            rule_include=payload.rule_include,
            rule_exclude=payload.rule_exclude,
            updated_by=actor.subject,
        )
    except KeyError as exc:
        AuditLogService().record(
            "rule.profile.update",
            request=request,
            status="failure",
            target=profile_id,
            details={"reason": "not_found"},
        )
        raise HTTPException(status_code=404, detail="룰 튜닝 프로필을 찾을 수 없습니다.") from exc
    except RuleTuningVersionConflict as exc:
        AuditLogService().record(
            "rule.profile.update",
            request=request,
            status="failure",
            target=profile_id,
            details={"reason": "version_conflict"},
        )
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuleTuningProfileError as exc:
        AuditLogService().record(
            "rule.profile.update",
            request=request,
            status="failure",
            target=profile_id,
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditLogService().record(
        "rule.profile.update",
        request=request,
        status="success",
        target=profile_id,
        details={
            "version": profile["version"],
            "name": profile["name"],
            "rule_include": profile["rule_include"],
            "rule_exclude": profile["rule_exclude"],
        },
    )
    return {"success": True, "profile": profile}


@router.delete("/rules/profiles/{profile_id}", response_class=JSONResponse)
async def delete_rule_tuning_profile(
    profile_id: str,
    request: Request,
    expected_version: int = Query(..., ge=1),
):
    try:
        removed = _profile_service().delete_profile(
            profile_id,
            expected_version=expected_version,
        )
    except KeyError as exc:
        AuditLogService().record(
            "rule.profile.delete",
            request=request,
            status="failure",
            target=profile_id,
            details={"reason": "not_found"},
        )
        raise HTTPException(status_code=404, detail="룰 튜닝 프로필을 찾을 수 없습니다.") from exc
    except RuleTuningVersionConflict as exc:
        AuditLogService().record(
            "rule.profile.delete",
            request=request,
            status="failure",
            target=profile_id,
            details={"reason": "version_conflict"},
        )
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuleTuningProfileError as exc:
        AuditLogService().record(
            "rule.profile.delete",
            request=request,
            status="failure",
            target=profile_id,
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    AuditLogService().record(
        "rule.profile.delete",
        request=request,
        status="success",
        target=profile_id,
        details={"version": removed["version"], "name": removed["name"]},
    )
    return {"success": True, "profile": removed}
