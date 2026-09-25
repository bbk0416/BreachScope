"""
규칙 API 라우터
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import logging

from breachscope.rules import load_rules
from breachscope.runtime_paths import default_rules_dir

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/rules", response_class=JSONResponse)
async def get_rules():
    """
    사용 가능한 탐지 규칙 목록 조회
    """
    try:
        rules_dir = default_rules_dir()
        if not rules_dir.exists():
            raise HTTPException(status_code=404, detail="규칙 디렉토리를 찾을 수 없습니다.")

        rules = load_rules(rules_dir)

        rules_list = []
        for rule in rules:
            rules_list.append({
                "id": rule.id,
                "title": rule.name,
                "severity": rule.severity,
                "mitre_technique": rule.mitre_technique,
                "field": rule.field,
                "pattern": rule.pattern,
            })

        return {
            "success": True,
            "count": len(rules_list),
            "rules": rules_list
        }
    except Exception as e:
        logger.error(f"규칙 로드 실패: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"규칙 로드 실패: {str(e)}")
