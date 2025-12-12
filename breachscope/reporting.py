from pathlib import Path
from typing import List, Dict, Any
from collections import Counter
import os
import re

from .schemas import Report, Finding, Event
from .attack import get_mitre_name
from .reporting.nlg import NLGTemplate
from .reporting.integrity import (
    generate_evidence_hash_list,
    generate_report_hash,
    calculate_file_hash,
)


def build_summary(findings: List[Finding]) -> Dict[str, object]:
    by_sev = Counter(f.severity for f in findings)
    by_rule = Counter(f.rule_name for f in findings)
    by_mitre = Counter((f.mitre_technique or "unknown") for f in findings)
    by_host = Counter((f.event.host or "unknown") for f in findings)
    # Resolve friendly names for MITRE techniques
    mitre_names: Dict[str, str] = {code: (get_mitre_name(code) if code != "unknown" else "Unknown") for code in by_mitre.keys()}
    # Maxima for simple bar charts
    max_sev = max(by_sev.values()) if by_sev else 0
    max_host = max(by_host.values()) if by_host else 0
    max_mitre = max(by_mitre.values()) if by_mitre else 0
    return {
        "total_findings": len(findings),
        "severity_counts": dict(by_sev),
        "rule_counts": dict(by_rule),
        "mitre_counts": dict(by_mitre),
        "host_counts": dict(by_host),
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


def render_html(report: Report, out_html: Path) -> None:
    # Redact by default to avoid AV false positives in saved reports
    redact = os.getenv("BS_REDACT", "1") != "0"
    if redact:
        for e in report.events:
            if e.command_line:
                e.command_line = _redact_string(e.command_line)
        for f in report.findings:
            if f.event and f.event.command_line:
                f.event.command_line = _redact_string(f.event.command_line)
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except Exception:
        # Very basic fallback
        html = _fallback_html(report)
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
    html = tmpl.render(report=report)
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


def maybe_render_pdf(html_path: Path, pdf_path: Path) -> bool:
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
