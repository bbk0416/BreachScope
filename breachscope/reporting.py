from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable
from collections import Counter, defaultdict
from dataclasses import asdict, is_dataclass
from copy import deepcopy
import os
import re
import json
import zipfile
from datetime import datetime, timezone

from .schemas import Report, Finding, Event
from .utils import parse_timestamp as _parse_ts
from .attack import get_mitre_name, get_mitre_tactic
from .reporting.nlg import NLGTemplate
from .reporting.integrity import (
    generate_evidence_hash_list,
    generate_report_hash,
    calculate_file_hash,
    calculate_event_hash,
)


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHTS = {"low": 5, "medium": 15, "high": 35, "critical": 60}


def _risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _build_risk_summary(findings: List[Finding]) -> Dict[str, object]:
    """탐지 결과를 0~100점 리스크 점수로 요약합니다."""
    if not findings:
        return {"score": 0, "level": "none", "formula": "no findings"}

    raw_score = sum(SEVERITY_WEIGHTS.get((f.severity or "").lower(), 10) for f in findings)
    unique_hosts = len({(f.event.host or "unknown") for f in findings})
    unique_techniques = len({(f.mitre_technique or "unknown") for f in findings})
    # 여러 호스트/기법에 걸쳐 있으면 사고 가능성이 커지므로 완만하게 가산합니다.
    adjusted = raw_score + max(0, unique_hosts - 1) * 8 + max(0, unique_techniques - 1) * 6
    score = min(100, adjusted)
    return {
        "score": score,
        "level": _risk_level(score),
        "raw_score": raw_score,
        "unique_hosts": unique_hosts,
        "unique_techniques": unique_techniques,
        "formula": "severity weights + host/technique spread bonus, capped at 100",
    }


def _top_findings(findings: List[Finding], limit: int = 5) -> List[Dict[str, object]]:
    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get((f.severity or "").lower(), 0), f.event.timestamp or ""),
        reverse=True,
    )
    return [
        {
            "severity": f.severity,
            "rule": f.rule_name,
            "mitre_technique": f.mitre_technique or "unknown",
            "mitre_name": get_mitre_name(f.mitre_technique),
            "host": f.event.host or "unknown",
            "timestamp": f.event.timestamp,
            "context": f.matched_context or f.matched_value or "",
        }
        for f in ordered[:limit]
    ]



def _technique_tactic(technique: Optional[str]) -> str:
    return get_mitre_tactic(technique)


def _iter_finding_texts(findings: Iterable[Finding]) -> Iterable[tuple[Finding, str]]:
    for finding in findings:
        values = [
            finding.event.command_line,
            finding.matched_value,
            finding.matched_context,
        ]
        for raw_key in ("message", "script", "payload", "Image", "CommandLine", "ParentCommandLine"):
            raw_value = finding.event.raw.get(raw_key) if finding.event and finding.event.raw else None
            if isinstance(raw_value, str):
                values.append(raw_value)
        for value in values:
            if value:
                yield finding, str(value)


def _indicator_bucket(indicators: Dict[str, Dict[str, Dict[str, object]]], kind: str, value: str, finding: Finding) -> None:
    if not value:
        return
    value = value.strip().strip('"\'()[]{}<>.,;')
    if not value:
        return
    bucket = indicators.setdefault(kind, {})
    row = bucket.setdefault(value, {
        "type": kind,
        "value": value,
        "count": 0,
        "hosts": set(),
        "rules": set(),
        "first_seen": None,
        "last_seen": None,
    })
    row["count"] = int(row["count"]) + 1
    if finding.event.host:
        row["hosts"].add(finding.event.host)
    if finding.rule_name:
        row["rules"].add(finding.rule_name)
    ts = finding.event.timestamp
    if ts:
        if row["first_seen"] is None or ts < row["first_seen"]:
            row["first_seen"] = ts
        if row["last_seen"] is None or ts > row["last_seen"]:
            row["last_seen"] = ts


def _extract_indicators(findings: List[Finding], limit_per_type: int = 50) -> Dict[str, List[Dict[str, object]]]:
    """명령줄/컨텍스트에서 대응자가 바로 복사해 쓸 수 있는 IOC 후보를 추출합니다.

    공격 시연 문자열을 실행 가능하게 만들지 않기 위해 리포트 본문은 기본 마스킹하지만,
    IOC 목록에는 URL/IP/도메인/해시/경로처럼 대응에 필요한 값만 구조화합니다.
    """
    indicators: Dict[str, Dict[str, Dict[str, object]]] = {}
    url_rx = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
    ip_rx = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")
    hash_rx = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
    path_rx = re.compile(r"\b[A-Za-z]:\\[^\s'\"<>|]+")
    domain_rx = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:local|lan|internal|corp|com|net|org|io|co|kr|dev|cloud|xyz)\b", re.IGNORECASE)

    for finding, text in _iter_finding_texts(findings):
        for url in url_rx.findall(text):
            _indicator_bucket(indicators, "url", url, finding)
        for ip in ip_rx.findall(text):
            # 사설 IP도 내부 확산 확인에 유용하므로 버리지 않습니다.
            _indicator_bucket(indicators, "ip", ip, finding)
        for hv in hash_rx.findall(text):
            kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(hv), "hash")
            _indicator_bucket(indicators, kind, hv.lower(), finding)
        for path in path_rx.findall(text):
            _indicator_bucket(indicators, "path", path, finding)
        for domain in domain_rx.findall(text):
            # URL에서 이미 나온 호스트도 도메인으로 따로 남겨 프록시/방화벽 검색이 쉽게 합니다.
            _indicator_bucket(indicators, "domain", domain.lower(), finding)

    result: Dict[str, List[Dict[str, object]]] = {}
    for kind, rows in indicators.items():
        normalized = []
        for row in rows.values():
            normalized.append({
                "type": row["type"],
                "value": row["value"],
                "count": row["count"],
                "hosts": sorted(row["hosts"]),
                "rules": sorted(row["rules"]),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            })
        result[kind] = sorted(normalized, key=lambda x: (-int(x["count"]), str(x["value"])))[:limit_per_type]
    return result


def _indicator_totals(indicators: Dict[str, List[Dict[str, object]]]) -> Dict[str, int]:
    return {kind: len(rows) for kind, rows in sorted(indicators.items())}


def _attack_coverage(findings: List[Finding]) -> List[Dict[str, object]]:
    by_tactic: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings:
        by_tactic[_technique_tactic(finding.mitre_technique)].append(finding)

    rows = []
    for tactic, tactic_findings in by_tactic.items():
        techniques = sorted({f.mitre_technique or "unknown" for f in tactic_findings})
        rows.append({
            "tactic": tactic,
            "findings": len(tactic_findings),
            "techniques": techniques,
            "highest_severity": max((f.severity or "low" for f in tactic_findings), key=lambda sev: SEVERITY_ORDER.get(sev.lower(), 0)),
            "hosts": sorted({f.event.host or "unknown" for f in tactic_findings}),
        })
    return sorted(rows, key=lambda row: (SEVERITY_ORDER.get(str(row["highest_severity"]).lower(), 0), int(row["findings"])), reverse=True)


def _incident_timeline(findings: List[Finding], limit: int = 30) -> List[Dict[str, object]]:
    def sort_key(f: Finding):
        dt = _parse_ts(f.event.timestamp)
        return (dt.isoformat() if dt else f.event.timestamp or "", SEVERITY_ORDER.get((f.severity or "").lower(), 0))

    rows = []
    prev_dt = None
    for finding in sorted(findings, key=sort_key)[:limit]:
        dt = _parse_ts(finding.event.timestamp)
        delta = None
        if dt and prev_dt:
            delta = int((dt - prev_dt).total_seconds())
        if dt:
            prev_dt = dt
        rows.append({
            "timestamp": finding.event.timestamp,
            "host": finding.event.host or "unknown",
            "user": finding.event.user or "unknown",
            "severity": finding.severity,
            "rule": finding.rule_name,
            "mitre_technique": finding.mitre_technique or "unknown",
            "mitre_name": get_mitre_name(finding.mitre_technique),
            "tactic": _technique_tactic(finding.mitre_technique),
            "delta_seconds": delta,
            "context": finding.matched_context or finding.matched_value or "",
        })
    return rows


def _false_positive_questions(findings: List[Finding]) -> List[str]:
    if not findings:
        return [
            "탐지 결과가 없더라도 로그 수집 범위가 실제 사고 시간대를 포함하는지 확인합니다.",
            "EDR/SIEM에서 이미 차단된 이벤트가 로컬 로그에 남지 않았는지 확인합니다.",
        ]
    questions = [
        "해당 명령을 실행한 사용자가 평소 해당 호스트에서 관리 작업을 수행하는 계정인가?",
        "탐지 시각 전후 30분에 승인된 배포, 패치, 원격지원 작업이 있었는가?",
        "부모 프로세스와 실행 경로가 조직 표준 도구 경로와 일치하는가?",
    ]
    techniques = {(f.mitre_technique or "").upper() for f in findings}
    if "T1105" in techniques:
        questions.append("탐지된 URL/도메인이 사내 업데이트 서버, 보안 솔루션, 공식 벤더 도메인인가?")
    if "T1003.001" in techniques:
        questions.append("LSASS 접근이 백업/보안 제품의 정상 수집 동작인지 벤더 문서와 에이전트 로그로 확인했는가?")
    if "T1070.001" in techniques:
        questions.append("로그 삭제가 운영 절차에 따른 보관 정책 작업인지, 누가 승인했는지 확인했는가?")
    return questions[:6]


def _containment_checklist(findings: List[Finding]) -> List[Dict[str, str]]:
    if not findings:
        return [
            {"priority": "P3", "task": "수집 범위 검증", "why": "로그가 부족하면 미탐 가능성이 커집니다."},
            {"priority": "P3", "task": "룰 최신화", "why": "조직 환경과 최근 침해지표를 반영해야 합니다."},
        ]
    checklist = [
        {"priority": "P1", "task": "영향 호스트 보존", "why": "전원 차단보다 네트워크 격리와 증거 보존을 우선 검토합니다."},
        {"priority": "P1", "task": "계정 사용 이력 확인", "why": "동일 사용자 계정의 다른 호스트 로그인 여부가 확산 판단의 핵심입니다."},
        {"priority": "P2", "task": "IOC 차단 후보 검토", "why": "URL/IP/도메인을 프록시·방화벽·EDR에서 교차 확인합니다."},
        {"priority": "P2", "task": "타임라인 확장", "why": "최초 실행 전후 이벤트를 연결해야 원인과 범위를 줄일 수 있습니다."},
    ]
    if any((f.mitre_technique or "").upper() == "T1003.001" for f in findings):
        checklist.insert(1, {"priority": "P1", "task": "자격증명 보호 조치", "why": "LSASS 덤프 정황은 비밀번호/토큰 탈취 가능성을 의미합니다."})
    return checklist[:6]



def _host_risk_summary(findings: List[Finding]) -> List[Dict[str, object]]:
    """호스트별 위험도를 계산해 대응 우선순위를 만듭니다."""
    by_host: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings:
        by_host[finding.event.host or "unknown"].append(finding)

    rows: List[Dict[str, object]] = []
    for host, host_findings in by_host.items():
        severities = Counter((f.severity or "unknown").lower() for f in host_findings)
        techniques = sorted({f.mitre_technique or "unknown" for f in host_findings})
        rules = Counter(f.rule_name for f in host_findings)
        score = min(100, sum(SEVERITY_WEIGHTS.get((f.severity or "").lower(), 10) for f in host_findings) + max(0, len(techniques) - 1) * 8)
        rows.append({
            "host": host,
            "score": score,
            "level": _risk_level(score),
            "findings": len(host_findings),
            "highest_severity": max((f.severity or "low" for f in host_findings), key=lambda sev: SEVERITY_ORDER.get(sev.lower(), 0)),
            "techniques": techniques,
            "severity_counts": dict(severities),
            "top_rule": rules.most_common(1)[0][0] if rules else "",
        })

    return sorted(rows, key=lambda row: (int(row["score"]), int(row["findings"])), reverse=True)


def _investigation_focus(findings: List[Finding]) -> List[str]:
    """분석자가 바로 따라갈 수 있는 확인 순서를 생성합니다."""
    if not findings:
        return [
            "탐지 결과가 없더라도 수집 범위가 충분한지 먼저 확인합니다.",
            "Security 4688, PowerShell Script Block, Sysmon ProcessCreate 로그가 빠졌다면 추가 수집합니다.",
        ]

    host_summary = _host_risk_summary(findings)
    first_host = host_summary[0]["host"] if host_summary else "영향 호스트"
    focus = [
        f"1순위 호스트 {first_host}에서 탐지 전후 30분의 프로세스 생성·네트워크·인증 로그를 타임라인으로 묶습니다.",
        "high/critical 탐지부터 사용자, 부모 프로세스, 실행 경로, 원격 접속 여부를 확인합니다.",
        "동일 명령 또는 동일 사용자가 다른 호스트에도 반복되었는지 검색해 확산 여부를 판단합니다.",
    ]
    if any((f.mitre_technique or "").upper() == "T1003.001" for f in findings):
        focus.append("LSASS 관련 탐지가 있으므로 계정 탈취 가능성을 별도 사고 트랙으로 분리합니다.")
    if any((f.mitre_technique or "").upper() == "T1070.001" for f in findings):
        focus.append("로그 삭제 정황이 있으므로 중앙 로그와 백업 로그를 우선 보존합니다.")
    return focus[:5]

def _executive_summary(findings: List[Finding], by_sev: Counter, by_host: Counter, by_mitre: Counter) -> List[str]:
    if not findings:
        return [
            "분석한 로그에서 활성화된 탐지 규칙에 매칭되는 의심 이벤트는 발견되지 않았습니다.",
            "단, 규칙 기반 분석 결과이므로 로그 수집 범위와 규칙 커버리지를 함께 확인해야 합니다.",
        ]

    top_host = by_host.most_common(1)[0][0] if by_host else "unknown"
    top_mitre = by_mitre.most_common(1)[0][0] if by_mitre else "unknown"
    top_mitre_name = get_mitre_name(top_mitre if top_mitre != "unknown" else None)
    high_count = by_sev.get("high", 0) + by_sev.get("critical", 0)
    lines = [
        f"총 {len(findings)}건의 의심 이벤트가 탐지되었고, 주요 영향 호스트는 {top_host}입니다.",
        f"가장 많이 관측된 ATT&CK 기법은 {top_mitre}({top_mitre_name})입니다.",
    ]
    if high_count:
        lines.append(f"high/critical 등급 탐지가 {high_count}건 있어 우선 확인이 필요합니다.")
    else:
        lines.append("현재 탐지는 low/medium 중심이므로 오탐 여부와 사용자 행위 맥락을 함께 확인하는 것이 좋습니다.")
    return lines


def _recommended_actions(findings: List[Finding]) -> List[str]:
    if not findings:
        return [
            "분석 대상 로그 범위가 충분한지 확인합니다. 특히 Security 4688, PowerShell, Sysmon 로그가 있으면 정확도가 올라갑니다.",
            "최신 침해지표와 조직 환경에 맞는 커스텀 규칙을 추가합니다.",
        ]

    techniques = {(f.mitre_technique or "").upper() for f in findings}
    rule_names = {(f.rule_name or "").lower() for f in findings}
    actions: List[str] = []

    if "T1059.001" in techniques or any("powershell" in r for r in rule_names):
        actions.append("PowerShell 실행 주체, 전체 명령줄, 스크립트 블록 로그를 확인하고 승인된 관리 작업인지 검증합니다.")
    if "T1105" in techniques or any("download" in r or "transfer" in r for r in rule_names):
        actions.append("탐지된 URL/IP 접속 이력과 다운로드 파일 해시를 확인하고, 프록시·방화벽 로그와 대조합니다.")
    if "T1003.001" in techniques or any("lsass" in r for r in rule_names):
        actions.append("LSASS 접근 흔적이 있으면 해당 호스트를 격리하고 계정 비밀번호·토큰 탈취 가능성을 우선 조사합니다.")
    if "T1070.001" in techniques or any("log clear" in r or "event log" in r for r in rule_names):
        actions.append("이벤트 로그 삭제 정황은 은폐 행위일 수 있으므로 중앙 로그, EDR, 백업 로그에서 동일 시간대를 복원합니다.")
    if "T1053.005" in techniques or "T1547.001" in techniques:
        actions.append("예약 작업과 Run 키를 확인하여 지속성 등록 여부를 점검하고 승인되지 않은 항목은 비활성화합니다.")

    actions.append("동일 사용자·동일 호스트 기준으로 전후 30분의 프로세스 생성, 네트워크 연결, 인증 이벤트를 묶어 타임라인을 재구성합니다.")
    # 순서 보존 중복 제거
    deduped = list(dict.fromkeys(actions))
    return deduped[:6]


def build_summary(findings: List[Finding]) -> Dict[str, object]:
    by_sev = Counter(f.severity for f in findings)
    by_rule = Counter(f.rule_name for f in findings)
    by_mitre = Counter((f.mitre_technique or "unknown") for f in findings)
    by_host = Counter((f.event.host or "unknown") for f in findings)
    # Resolve friendly names for MITRE techniques
    mitre_names: Dict[str, str] = {code: (get_mitre_name(code) if code != "unknown" else "Unknown") for code in by_mitre.keys()}
    indicators = _extract_indicators(findings)
    # Maxima for simple bar charts
    max_sev = max(by_sev.values()) if by_sev else 0
    max_host = max(by_host.values()) if by_host else 0
    max_mitre = max(by_mitre.values()) if by_mitre else 0
    return {
        "total_findings": len(findings),
        "risk": _build_risk_summary(findings),
        "executive_summary": _executive_summary(findings, by_sev, by_host, by_mitre),
        "recommended_actions": _recommended_actions(findings),
        "top_findings": _top_findings(findings),
        "host_risk_summary": _host_risk_summary(findings),
        "investigation_focus": _investigation_focus(findings),
        "incident_timeline": _incident_timeline(findings),
        "attack_coverage": _attack_coverage(findings),
        "indicators": indicators,
        "indicator_totals": _indicator_totals(indicators),
        "false_positive_questions": _false_positive_questions(findings),
        "containment_checklist": _containment_checklist(findings),
        "severity_counts": dict(by_sev),
        "rule_counts": dict(by_rule),
        "mitre_counts": dict(by_mitre),
        "host_counts": dict(by_host),
        "affected_hosts": sorted(by_host.keys()),
        "mitre_names": mitre_names,
        "max_severity": max_sev,
        "max_host": max_host,
        "max_mitre": max_mitre,
    }


def _redact_string(s: str) -> str:
    if not s:
        return s
    text = s
    # Mask common trigger tokens conservatively
    patterns = [
        re.compile(r"mimikatz", re.IGNORECASE),
        re.compile(r"invoke-?mimikatz", re.IGNORECASE),
        re.compile(r"-enc(odedcommand)?\b", re.IGNORECASE),
        re.compile(r"new-object\s+net\.webclient", re.IGNORECASE),
        re.compile(r"invoke-webrequest|wget|curl", re.IGNORECASE),
    ]
    for rx in patterns:
        text = rx.sub("[REDACTED]", text)
    # Elide long base64-like blobs
    text = re.sub(r"[A-Za-z0-9+/=]{24,}", "[BASE64...REDACTED]", text)
    return text


def _redacted_report_copy(report: Report) -> Report:
    """HTML 렌더링용 사본만 마스킹합니다.

    원본 Report 객체를 직접 바꾸면 이후 JSON/CSV/manifest 해시가 원본 증거가 아니라
    마스킹된 값 기준으로 생성될 수 있으므로, 출력용 사본을 사용합니다.
    """
    copied = deepcopy(report)
    for e in copied.events:
        if e.command_line:
            e.command_line = _redact_string(e.command_line)
    for f in copied.findings:
        if f.event and f.event.command_line:
            f.event.command_line = _redact_string(f.event.command_line)
        if f.matched_value:
            f.matched_value = _redact_string(f.matched_value)
        if f.matched_context:
            f.matched_context = _redact_string(f.matched_context)
    return copied


def render_html(report: Report, out_html: Path) -> None:
    # Redact by default to avoid AV false positives in saved reports
    redact = os.getenv("BS_REDACT", "1") != "0"
    render_report = _redacted_report_copy(report) if redact else report
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except Exception:
        # Very basic fallback
        html = _fallback_html(render_report)
        out_html.write_text(html, encoding="utf-8")
        return

    tmpl_dir = Path(__file__).parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template("report.html.j2")
    html = tmpl.render(report=render_report)
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html, encoding="utf-8")


def _fallback_html(report: Report) -> str:
    rows = []
    for f in report.findings:
        rows.append(
            f"<tr><td>{f.severity}</td><td>{f.rule_name}</td><td>{f.mitre_technique or ''}</td>"
            f"<td>{f.event.timestamp}</td><td>{(f.event.command_line or '')[:120]}</td></tr>"
        )
    return (
        "<html><head><meta charset='utf-8'><title>BreachScope Report</title>"
        "<style>body{font-family:Segoe UI,Arial} table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ddd;padding:6px} th{background:#f2f2f2}</style></head><body>"
        f"<h1>BreachScope Report</h1><p>Total findings: {len(report.findings)}</p>"
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>MITRE</th><th>Time</th><th>Command</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></body></html>"
    )


def maybe_render_pdf(html_path: Path, pdf_path: Path, report: Report | None = None) -> bool:
    """PDF 리포트를 생성합니다.

    v9부터는 ReportLab 기반 한글 경영진/초동대응 PDF를 우선 생성합니다.
    ReportLab 또는 한글 PDF 생성이 실패하면 기존 HTML -> PDF(WeasyPrint) 방식으로
    후퇴하여 호환성을 유지합니다.
    """
    if report is not None:
        try:
            from breachscope.reporting.pdf_report import export_korean_pdf

            if export_korean_pdf(report, pdf_path):
                return True
        except Exception:
            pass

    try:
        from weasyprint import HTML
    except Exception:
        return False
    HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    return True


def export_json(report: Report, out_json: Path, redact: bool = True) -> None:
    def red(s: str | None) -> str | None:
        return _redact_string(s) if (s and redact) else s

    data: Dict[str, Any] = {
        "summary": report.summary,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "mitre_technique": f.mitre_technique,
                "mitre_name": get_mitre_name(f.mitre_technique),
                "event": {
                    "timestamp": f.event.timestamp,
                    "host": f.event.host,
                    "source": f.event.source,
                    "event_id": f.event.event_id,
                    "user": f.event.user,
                    "command_line": red(f.event.command_line),
                },
                "matched_value": red(f.matched_value),
                "matched_context": red(f.matched_context),
            }
            for f in report.findings
        ],
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    import json as _json

    out_json.write_text(_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def export_csv(report: Report, out_csv: Path, redact: bool = True) -> None:
    import csv

    def red(s: str | None) -> str | None:
        return _redact_string(s) if (s and redact) else s

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "timestamp",
            "host",
            "rule",
            "severity",
            "mitre",
            "command_excerpt",
            "matched_context",
        ])
        for fi in report.findings:
            cmd = red((fi.event.command_line or "")[:160]) or ""
            ctx = red((fi.matched_context or "")[:160]) or ""
            w.writerow([
                fi.event.timestamp,
                fi.event.host,
                fi.rule_name,
                fi.severity,
                fi.mitre_technique or "",
                cmd,
                ctx,
            ])


def export_iocs_csv(report: Report, out_csv: Path) -> None:
    """추출 IOC 후보를 별도 CSV로 저장합니다."""
    import csv

    indicators = (report.summary or {}).get("indicators", {}) or {}
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "count", "hosts", "rules", "first_seen", "last_seen"])
        for kind in sorted(indicators.keys()):
            for row in indicators.get(kind, []):
                w.writerow([
                    row.get("type", kind),
                    row.get("value", ""),
                    row.get("count", 0),
                    ";".join(row.get("hosts", []) or []),
                    ";".join(row.get("rules", []) or []),
                    row.get("first_seen", ""),
                    row.get("last_seen", ""),
                ])

def _to_plain(obj: Any) -> Any:
    """dataclass/Path 등 JSON 직렬화가 애매한 값을 안전하게 변환합니다."""
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_plain(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _to_plain(v) for k, v in obj.items()}
    return obj


def build_case_manifest(report: Report, artifact_paths: Optional[List[Path]] = None) -> Dict[str, Any]:
    """리포트/증거의 무결성 확인용 manifest 데이터를 생성합니다."""
    artifact_paths = artifact_paths or []
    generated_at = datetime.now(timezone.utc).isoformat()
    evidence_hashes = generate_evidence_hash_list(
        report.events,
        report.findings,
        report.chains,
        report.scenarios,
        sample_limit=None,
    )
    report_core = {
        "summary": report.summary,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "mitre_technique": f.mitre_technique,
                "event_hash": calculate_event_hash(f.event),
                "matched_value": f.matched_value,
            }
            for f in report.findings
        ],
        "event_hashes": [item["hash"] for item in evidence_hashes["events"]],
    }
    artifacts = []
    for artifact in artifact_paths:
        if artifact and artifact.exists() and artifact.is_file():
            artifacts.append({
                "name": artifact.name,
                "path": str(artifact),
                "size_bytes": artifact.stat().st_size,
                "sha256": calculate_file_hash(artifact),
            })

    return {
        "schema_version": "1.0",
        "tool": "BreachScope",
        "generated_at": generated_at,
        "case": {
            "total_events": len(report.events),
            "total_findings": len(report.findings),
            "risk_score": (report.summary.get("risk") or {}).get("score", 0),
            "risk_level": (report.summary.get("risk") or {}).get("level", "none"),
            "affected_hosts": report.summary.get("affected_hosts", []),
        },
        "report_sha256": generate_report_hash(report_core),
        "evidence_hashes": evidence_hashes,
        "artifacts": artifacts,
    }


def export_manifest(report: Report, out_manifest: Path, artifact_paths: Optional[List[Path]] = None) -> Dict[str, Any]:
    manifest = build_case_manifest(report, artifact_paths=artifact_paths)
    out_manifest.parent.mkdir(parents=True, exist_ok=True)
    out_manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return manifest


def export_case_package(out_zip: Path, artifact_paths: List[Path]) -> Path:
    """HTML/JSON/CSV/manifest를 하나의 케이스 ZIP으로 묶습니다."""
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in artifact_paths:
            if path and path.exists() and path.is_file():
                zf.write(path, arcname=path.name)
    return out_zip

