from pathlib import Path

from breachscope.reporting import maybe_render_pdf
from breachscope.schemas import Event, Finding, Report


def _sample_report() -> Report:
    event = Event(
        timestamp="2026-06-11T00:00:00Z",
        host="WS-01",
        source="ProcessCreate",
        event_id="4688",
        user="CORP\\alice",
        command_line="powershell.exe -encodedcommand AAAABBBBCCCCDDDD",
    )
    finding = Finding(
        rule_id="BS-TEST-001",
        rule_name="Suspicious PowerShell",
        severity="high",
        mitre_technique="T1059.001",
        event=event,
        matched_value="powershell.exe",
        matched_context="PowerShell encoded command",
    )
    summary = {
        "total_findings": 1,
        "risk": {"score": 72, "level": "high", "unique_hosts": 1, "unique_techniques": 1},
        "executive_summary": ["총 1건의 의심 이벤트가 탐지되었습니다."],
        "recommended_actions": ["PowerShell 실행 주체와 명령줄을 확인합니다."],
        "top_findings": [{"severity": "high", "rule": "Suspicious PowerShell", "mitre_technique": "T1059.001", "host": "WS-01", "timestamp": "2026-06-11T00:00:00Z"}],
        "host_risk_summary": [{"host": "WS-01", "score": 72, "level": "high", "findings": 1, "techniques": ["T1059.001"]}],
        "incident_timeline": [{"timestamp": "2026-06-11T00:00:00Z", "host": "WS-01", "user": "CORP\\alice", "severity": "high", "tactic": "Execution", "rule": "Suspicious PowerShell"}],
        "attack_coverage": [{"tactic": "Execution", "findings": 1, "highest_severity": "high", "techniques": ["T1059.001"], "hosts": ["WS-01"]}],
        "indicator_totals": {"domain": 1},
        "containment_checklist": [{"priority": "P1", "task": "영향 호스트 보존", "why": "증거 보존"}],
        "false_positive_questions": ["승인된 작업이 있었는가?"],
    }
    return Report(summary=summary, findings=[finding], events=[event])


def test_korean_pdf_report_created(tmp_path: Path):
    html = tmp_path / "report.html"
    pdf = tmp_path / "report.pdf"
    html.write_text("<html><body>BreachScope</body></html>", encoding="utf-8")

    assert maybe_render_pdf(html, pdf, _sample_report()) is True
    assert pdf.exists()
    assert pdf.stat().st_size > 1000
    assert pdf.read_bytes().startswith(b"%PDF")
