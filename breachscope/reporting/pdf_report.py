"""Korean executive PDF report generation for BreachScope.

This module intentionally uses ReportLab instead of converting the full HTML page.
The HTML dashboard is optimized for interactive exploration, while this PDF is a
compact handoff document for managers, customers, and incident responders.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _first_existing(candidates: Iterable[Optional[str]]) -> Optional[str]:
    for raw in candidates:
        if not raw:
            continue
        path = Path(raw).expanduser()
        if path.exists() and path.is_file():
            return str(path)
    return None


def _register_pdf_fonts() -> Tuple[str, str, str]:
    """Register a Korean-capable font if available and return font names.

    The project does not bundle font files. Operators can point to internal fonts
    with BS_PDF_FONT_REGULAR and BS_PDF_FONT_BOLD. On common Korean/Linux/Windows
    workstations we auto-detect NanumGothic or Malgun Gothic.
    """
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    regular_candidates = [
        os.getenv("BS_PDF_FONT_REGULAR"),
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        "/usr/share/fonts/truetype/nanum/NanumBarunGothic.ttf",
        "/usr/share/fonts/truetype/unfonts-core/UnBatang.ttf",
        "C:/Windows/Fonts/malgun.ttf",
        "C:/Windows/Fonts/gulim.ttc",
        "/Library/Fonts/NanumGothic.ttf",
    ]
    bold_candidates = [
        os.getenv("BS_PDF_FONT_BOLD"),
        "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf",
        "/usr/share/fonts/truetype/nanum/NanumBarunGothicBold.ttf",
        "/usr/share/fonts/truetype/unfonts-core/UnBatangBold.ttf",
        "C:/Windows/Fonts/malgunbd.ttf",
        "/Library/Fonts/NanumGothicBold.ttf",
    ]
    regular_path = _first_existing(regular_candidates)
    bold_path = _first_existing(bold_candidates) or regular_path

    if regular_path:
        try:
            pdfmetrics.registerFont(TTFont("BreachScopeKorean", regular_path))
            if bold_path:
                pdfmetrics.registerFont(TTFont("BreachScopeKorean-Bold", bold_path))
            else:
                pdfmetrics.registerFont(TTFont("BreachScopeKorean-Bold", regular_path))
            return "BreachScopeKorean", "BreachScopeKorean-Bold", regular_path
        except Exception:
            # Fall through to built-in fonts. This keeps PDF generation available,
            # though Korean glyph rendering may depend on the viewer.
            pass
    return "Helvetica", "Helvetica-Bold", "built-in Helvetica fallback"


def _risk_color(level: str):
    from reportlab.lib import colors

    level = (level or "none").lower()
    if level == "critical":
        return colors.HexColor("#7f1d1d")
    if level == "high":
        return colors.HexColor("#b91c1c")
    if level == "medium":
        return colors.HexColor("#d97706")
    if level == "low":
        return colors.HexColor("#15803d")
    return colors.HexColor("#334155")


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _short(text: Any, limit: int = 90) -> str:
    value = "" if text is None else str(text)
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _kv_table(rows: List[Tuple[str, Any]], styles: Dict[str, Any]):
    from reportlab.platypus import Table
    from reportlab.lib import colors
    from reportlab.lib.units import mm

    data = [[styles["label"](k), styles["body"](_short(v, 120))] for k, v in rows]
    table = Table(data, colWidths=[38 * mm, 112 * mm], hAlign="LEFT")
    table.setStyle([
        ("FONTNAME", (0, 0), (-1, -1), styles["font"]),
        ("FONTNAME", (0, 0), (0, -1), styles["bold_font"]),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])
    return table


def _simple_table(headers: List[str], rows: List[List[Any]], styles: Dict[str, Any], widths: Optional[List[Any]] = None):
    from reportlab.platypus import Table
    from reportlab.lib import colors

    data = [[styles["th"](h) for h in headers]]
    data.extend([[styles["td"](_short(cell, 110)) for cell in row] for row in rows])
    if len(data) == 1:
        data.append([styles["td"]("데이터 없음")] + [styles["td"]("") for _ in headers[1:]])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle([
        ("FONTNAME", (0, 0), (-1, -1), styles["font"]),
        ("FONTNAME", (0, 0), (-1, 0), styles["bold_font"]),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ])
    return table


def _bullet_list(title: str, items: List[Any], story: List[Any], styles: Dict[str, Any], limit: int = 6) -> None:
    from reportlab.platypus import Paragraph, Spacer, ListFlowable, ListItem
    from reportlab.lib.units import mm

    story.append(Paragraph(title, styles["h2_style"]))
    clean = [_short(x, 180) for x in items[:limit] if x]
    if not clean:
        clean = ["데이터 없음"]
    story.append(ListFlowable(
        [ListItem(Paragraph(item, styles["body_style"]), bulletColor=styles["bullet_color"]) for item in clean],
        bulletType="bullet",
        start="circle",
        leftIndent=12,
    ))
    story.append(Spacer(1, 4 * mm))


def export_korean_pdf(report: Any, pdf_path: Path, *, title: str = "BreachScope 침해사고 초동분석 보고서") -> bool:
    """Create a compact Korean PDF handoff report.

    Returns True when a PDF file was created. The caller can fall back to another
    renderer if this function returns False.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
        )
    except Exception:
        return False

    font_name, bold_font, font_source = _register_pdf_fonts()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    summary = _as_dict(getattr(report, "summary", {}))
    risk = _as_dict(summary.get("risk"))
    total_events = len(getattr(report, "events", []) or [])
    total_findings = int(summary.get("total_findings") or len(getattr(report, "findings", []) or []))
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    stylesheet = getSampleStyleSheet()
    body = ParagraphStyle(
        "BreachBody",
        parent=stylesheet["BodyText"],
        fontName=font_name,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#111827"),
        wordWrap="CJK",
        spaceAfter=4,
    )
    small = ParagraphStyle("BreachSmall", parent=body, fontSize=7.5, leading=10, textColor=colors.HexColor("#475569"))
    h1 = ParagraphStyle("BreachH1", parent=body, fontName=bold_font, fontSize=20, leading=25, alignment=TA_CENTER, spaceAfter=8)
    h2 = ParagraphStyle("BreachH2", parent=body, fontName=bold_font, fontSize=13, leading=17, textColor=colors.HexColor("#0f172a"), spaceBefore=8, spaceAfter=6)
    h3 = ParagraphStyle("BreachH3", parent=body, fontName=bold_font, fontSize=10.5, leading=14, textColor=colors.HexColor("#334155"), spaceBefore=4, spaceAfter=4)
    label_style = ParagraphStyle("BreachLabel", parent=small, fontName=bold_font)
    table_header = ParagraphStyle("BreachTH", parent=small, fontName=bold_font, textColor=colors.white)
    table_cell = ParagraphStyle("BreachTD", parent=small, wordWrap="CJK")
    score_style = ParagraphStyle(
        "BreachScore",
        parent=body,
        fontName=bold_font,
        fontSize=36,
        leading=42,
        alignment=TA_CENTER,
        textColor=_risk_color(str(risk.get("level") or "none")),
    )

    style_helpers = {
        "font": font_name,
        "bold_font": bold_font,
        "body_style": body,
        "h2_style": h2,
        "bullet_color": colors.HexColor("#2563eb"),
        "label": lambda value: Paragraph(str(value), label_style),
        "body": lambda value: Paragraph(str(value), body),
        "th": lambda value: Paragraph(str(value), table_header),
        "td": lambda value: Paragraph(str(value), table_cell),
    }

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=17 * mm,
        title=title,
        author="BreachScope",
        subject="DFIR executive report",
    )

    def draw_page(canvas, doc_obj):
        canvas.saveState()
        width, height = A4
        canvas.setFont(font_name, 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(16 * mm, height - 10 * mm, "BreachScope - Confidential DFIR Report")
        canvas.drawRightString(width - 16 * mm, height - 10 * mm, generated_at)
        canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
        canvas.line(16 * mm, height - 12 * mm, width - 16 * mm, height - 12 * mm)
        canvas.line(16 * mm, 13 * mm, width - 16 * mm, 13 * mm)
        canvas.drawString(16 * mm, 8.5 * mm, "본 문서는 룰 기반 초동분석 결과입니다. 최종 결론 전 원본 로그와 업무 맥락을 확인하십시오.")
        canvas.drawRightString(width - 16 * mm, 8.5 * mm, f"Page {doc_obj.page}")
        canvas.restoreState()

    story: List[Any] = []
    story.append(Paragraph(title, h1))
    story.append(Paragraph("Executive handoff report / 고객 제출용 요약", small))
    story.append(Spacer(1, 6 * mm))

    score_card = Table(
        [[
            Paragraph("Risk Score", h3),
            Paragraph("탐지 현황", h3),
            Paragraph("분석 범위", h3),
        ], [
            Paragraph(f"{risk.get('score', 0)}", score_style),
            Paragraph(f"<b>{total_findings}</b> findings<br/><b>{risk.get('level', 'none')}</b> level", body),
            Paragraph(f"<b>{total_events}</b> events<br/><b>{risk.get('unique_hosts', 0)}</b> hosts / <b>{risk.get('unique_techniques', 0)}</b> techniques", body),
        ]],
        colWidths=[52 * mm, 52 * mm, 52 * mm],
        hAlign="CENTER",
    )
    score_card.setStyle([
        ("FONTNAME", (0, 0), (-1, -1), font_name),
        ("FONTNAME", (0, 0), (-1, 0), bold_font),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ])
    story.append(score_card)
    story.append(Spacer(1, 5 * mm))

    story.append(_kv_table([
        ("생성 시각", generated_at),
        ("PDF 폰트", Path(font_source).name if font_source != "built-in Helvetica fallback" else font_source),
        ("분석 성격", "규칙 기반 초동분석 - 탐지 결과는 원본 로그/업무 맥락으로 재검증 필요"),
        ("기밀 등급", "Confidential / 내부 공유 또는 고객 제출 전 검토 권장"),
    ], style_helpers))

    _bullet_list("1. 경영진 요약", _as_list(summary.get("executive_summary")), story, style_helpers, limit=5)
    _bullet_list("2. 우선 조치 권고", _as_list(summary.get("recommended_actions")), story, style_helpers, limit=6)

    story.append(Paragraph("3. 우선 확인 탐지 Top 5", h2))
    top_rows = []
    for row in _as_list(summary.get("top_findings"))[:5]:
        if isinstance(row, dict):
            top_rows.append([
                row.get("severity", ""),
                row.get("rule", ""),
                row.get("mitre_technique", ""),
                row.get("host", ""),
                row.get("timestamp", ""),
            ])
    story.append(_simple_table(["등급", "룰", "MITRE", "호스트", "시간"], top_rows, style_helpers, widths=[18*mm, 52*mm, 24*mm, 28*mm, 35*mm]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("4. 호스트별 위험도", h2))
    host_rows = []
    for row in _as_list(summary.get("host_risk_summary"))[:8]:
        if isinstance(row, dict):
            host_rows.append([
                row.get("host", ""),
                f"{row.get('score', 0)}/100",
                row.get("level", ""),
                row.get("findings", 0),
                ", ".join(_as_list(row.get("techniques"))[:4]),
            ])
    story.append(_simple_table(["호스트", "점수", "레벨", "탐지", "주요 기법"], host_rows, style_helpers, widths=[35*mm, 22*mm, 24*mm, 18*mm, 58*mm]))

    story.append(Paragraph("5. 사고 타임라인", h2))
    timeline_rows = []
    for row in _as_list(summary.get("incident_timeline"))[:12]:
        if isinstance(row, dict):
            timeline_rows.append([
                row.get("timestamp", ""),
                row.get("host", ""),
                row.get("user", ""),
                row.get("severity", ""),
                row.get("tactic", ""),
                row.get("rule", ""),
            ])
    story.append(_simple_table(["시간", "호스트", "사용자", "등급", "전술", "룰"], timeline_rows, style_helpers, widths=[35*mm, 25*mm, 30*mm, 16*mm, 28*mm, 35*mm]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("6. ATT&CK 전술 커버리지", h2))
    attack_rows = []
    for row in _as_list(summary.get("attack_coverage"))[:10]:
        if isinstance(row, dict):
            attack_rows.append([
                row.get("tactic", ""),
                row.get("findings", 0),
                row.get("highest_severity", ""),
                ", ".join(_as_list(row.get("techniques"))[:5]),
                ", ".join(_as_list(row.get("hosts"))[:4]),
            ])
    story.append(_simple_table(["전술", "탐지", "최고 등급", "기법", "호스트"], attack_rows, style_helpers, widths=[35*mm, 18*mm, 24*mm, 50*mm, 35*mm]))
    story.append(Spacer(1, 4 * mm))

    indicators = _as_dict(summary.get("indicator_totals"))
    story.append(Paragraph("7. IOC 후보 요약", h2))
    indicator_rows = [[k, v] for k, v in sorted(indicators.items())]
    story.append(_simple_table(["유형", "개수"], indicator_rows, style_helpers, widths=[45*mm, 35*mm]))
    story.append(Spacer(1, 4 * mm))

    _bullet_list("8. 초동대응 체크리스트", [f"{x.get('priority', '')} - {x.get('task', '')}: {x.get('why', '')}" for x in _as_list(summary.get("containment_checklist")) if isinstance(x, dict)], story, style_helpers, limit=8)
    _bullet_list("9. 오탐 확인 질문", _as_list(summary.get("false_positive_questions")), story, style_helpers, limit=8)

    story.append(Paragraph("10. 증거 무결성 및 산출물", h2))
    story.append(Paragraph(
        "HTML/JSON/CSV/IOC/룰 카탈로그/Manifest/케이스 ZIP은 동일 케이스 산출물로 묶이며, Manifest에는 이벤트/탐지/파일 SHA-256 해시가 포함됩니다.",
        body,
    ))
    story.append(Paragraph("원본 증거 보존과 별도 검증을 위해 PDF는 요약 문서로 사용하고, 세부 증거는 JSON/CSV/Manifest를 함께 제출하십시오.", body))
    story.append(Spacer(1, 3 * mm))


    try:
        doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
        return pdf_path.exists() and pdf_path.stat().st_size > 0
    except Exception:
        return False
