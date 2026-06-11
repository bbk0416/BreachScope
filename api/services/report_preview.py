"""리포트 미리보기 데이터 생성 유틸리티.

웹 UI는 전체 HTML/JSON 산출물을 다운로드하기 전에 핵심 지표를 즉시 확인할 수 있어야 합니다.
이 모듈은 report.json에서 안전한 요약 카드, 차트, 타임라인용 최소 데이터를 추출합니다.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import json


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _trim_text(value: Any, limit: int = 180) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _sorted_count_rows(counts: Dict[str, Any], limit: int = 8) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for key, value in counts.items():
        try:
            count = int(value)
        except (TypeError, ValueError):
            count = 0
        rows.append({"name": str(key), "count": count})
    rows.sort(key=lambda row: (-row["count"], row["name"]))
    return rows[:limit]


def build_preview(report_data: Dict[str, Any], max_findings: int = 8, max_timeline: int = 12) -> Dict[str, Any]:
    """report.json 전체 데이터에서 웹 대시보드용 핵심 필드만 뽑습니다."""
    summary = _safe_dict(report_data.get("summary"))
    risk = _safe_dict(summary.get("risk"))
    rule_pack = _safe_dict(summary.get("rule_pack"))

    top_findings = []
    for row in _safe_list(summary.get("top_findings"))[:max_findings]:
        item = _safe_dict(row)
        top_findings.append({
            "severity": item.get("severity", "unknown"),
            "rule": item.get("rule", ""),
            "mitre_technique": item.get("mitre_technique", "unknown"),
            "mitre_name": item.get("mitre_name", "Unknown"),
            "host": item.get("host", "unknown"),
            "timestamp": item.get("timestamp", ""),
            "context": _trim_text(item.get("context"), 160),
        })

    timeline = []
    for row in _safe_list(summary.get("incident_timeline"))[:max_timeline]:
        item = _safe_dict(row)
        timeline.append({
            "timestamp": item.get("timestamp", ""),
            "delta_seconds": item.get("delta_seconds"),
            "host": item.get("host", "unknown"),
            "user": item.get("user", "unknown"),
            "severity": item.get("severity", "unknown"),
            "tactic": item.get("tactic", "unknown"),
            "rule": item.get("rule", ""),
            "context": _trim_text(item.get("context"), 140),
        })

    tactic_coverage = []
    for row in _safe_list(summary.get("attack_coverage"))[:10]:
        item = _safe_dict(row)
        tactic_coverage.append({
            "tactic": item.get("tactic", "unknown"),
            "findings": item.get("findings", 0),
            "highest_severity": item.get("highest_severity", "unknown"),
            "techniques": _safe_list(item.get("techniques"))[:8],
            "hosts": _safe_list(item.get("hosts"))[:8],
        })

    return {
        "risk": {
            "score": int(risk.get("score") or 0),
            "level": risk.get("level", "none"),
            "unique_hosts": int(risk.get("unique_hosts") or 0),
            "unique_techniques": int(risk.get("unique_techniques") or 0),
        },
        "total_findings": int(summary.get("total_findings") or 0),
        "executive_summary": _safe_list(summary.get("executive_summary"))[:4],
        "recommended_actions": _safe_list(summary.get("recommended_actions"))[:5],
        "containment_checklist": _safe_list(summary.get("containment_checklist"))[:5],
        "false_positive_questions": _safe_list(summary.get("false_positive_questions"))[:4],
        "top_findings": top_findings,
        "incident_timeline": timeline,
        "host_risk_summary": _safe_list(summary.get("host_risk_summary"))[:8],
        "attack_coverage": tactic_coverage,
        "indicator_totals": _safe_dict(summary.get("indicator_totals")),
        "severity_counts": _sorted_count_rows(_safe_dict(summary.get("severity_counts"))),
        "host_counts": _sorted_count_rows(_safe_dict(summary.get("host_counts"))),
        "mitre_counts": _sorted_count_rows(_safe_dict(summary.get("mitre_counts"))),
        "sample_scenarios": _safe_list(summary.get("sample_scenarios"))[:10],
        "rule_pack": {
            "total_rules": int(rule_pack.get("total_rules") or 0),
            "unique_techniques": int(rule_pack.get("unique_techniques") or 0),
            "coverage_percent_core_windows": rule_pack.get("coverage_percent_core_windows", 0),
            "tactic_coverage": _safe_list(rule_pack.get("tactic_coverage"))[:10],
        },
    }


def load_preview(work_dir: str | Path) -> Dict[str, Any]:
    work_path = Path(work_dir)
    report_json = work_path / "out" / "report.json"
    if not report_json.exists():
        raise FileNotFoundError(f"report.json not found: {report_json}")
    data = json.loads(report_json.read_text(encoding="utf-8"))
    return build_preview(data)
