"""Public demo-pack builder for BreachScope.

The release bundle answers "can I install this?". The demo pack answers a
more practical portfolio/sales question: "what should I open first to
understand and show the project in five minutes?"
"""
from __future__ import annotations

import json
import os
import shutil
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZIP_DEFLATED, ZipFile

from breachscope.demo_scenarios import list_demo_scenarios, write_all_demo_scenarios
from breachscope.pipeline import run_pipeline
from breachscope.project_readiness import run_project_readiness
from breachscope.quality_gate import run_quality_gate
from breachscope.release import get_project_metadata, sha256_file
from breachscope.rulepack import summarize_rules
from breachscope.rules import load_rules


@dataclass(frozen=True)
class DemoPackArtifact:
    path: str
    size_bytes: int
    sha256: str
    purpose: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@contextmanager
def _pushd(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    risk = summary.get("risk") or {}
    rule_pack = summary.get("rule_pack") or {}
    sample_scenarios = summary.get("sample_scenarios") or []
    host_risk = summary.get("host_risk_summary") or []
    attack_coverage = summary.get("attack_coverage") or []
    indicator_totals = summary.get("indicator_totals") or {}
    return {
        "total_events": len(report.get("events", [])) if isinstance(report, dict) else 0,
        "total_findings": int(summary.get("total_findings") or 0),
        "risk_score": int(risk.get("score") or 0),
        "risk_level": str(risk.get("level") or "none"),
        "affected_hosts": int(risk.get("unique_hosts") or len(host_risk) or 0),
        "unique_techniques": int(risk.get("unique_techniques") or 0),
        "indicator_totals": indicator_totals,
        "rule_count": int(rule_pack.get("total_rules") or 0),
        "rule_techniques": int(rule_pack.get("unique_techniques") or 0),
        "rule_coverage": float(rule_pack.get("coverage_percent_core_windows") or 0.0),
        "scenario_count": len(sample_scenarios),
        "top_hosts": host_risk[:5],
        "top_tactics": attack_coverage[:5],
    }


def _md_table(headers: list[str], rows: Iterable[Iterable[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return lines


def _write_file(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.rstrip() + "\n", encoding="utf-8")


def _executive_overview(meta: dict[str, Any], demo: dict[str, Any], readiness: dict[str, Any], quality: dict[str, Any]) -> str:
    lines = [
        "# BreachScope Demo Pack Executive Overview",
        "",
        "BreachScope는 Windows 이벤트 로그/JSONL 로그를 분석해 ATT&CK 매핑, IOC 후보, 사고 타임라인, 케이스 이력, 한글 PDF 보고서까지 생성하는 제품형 DFIR 콘솔입니다.",
        "",
        "## Demo result snapshot",
        "",
        f"- Version: **{meta.get('version', 'unknown')}**",
        f"- Generated at: `{meta.get('generated_at', '')}`",
        f"- Demo events: **{demo['total_events']}**",
        f"- Findings: **{demo['total_findings']}**",
        f"- Risk: **{demo['risk_score']}/100 ({demo['risk_level']})**",
        f"- Affected hosts: **{demo['affected_hosts']}**",
        f"- Unique ATT&CK techniques in findings: **{demo['unique_techniques']}**",
        f"- Rulepack: **{demo['rule_count']} rules / {demo['rule_techniques']} techniques / {demo['rule_coverage']}% core Windows coverage**",
        f"- Built-in scenarios represented: **{demo['scenario_count']}**",
        f"- Project readiness: **{readiness.get('score')}/100 ({readiness.get('status')})**",
        f"- Quality gate: **{quality.get('score')}/100 ({quality.get('status')})**",
        "",
        "## What to open first",
        "",
        "1. `reports/breachscope_demo_report.html` — 웹에서 볼 수 있는 전체 분석 리포트",
        "2. `reports/breachscope_demo_report.pdf` — 고객 제출/면접 설명용 한글 PDF 리포트",
        "3. `02_DEMO_WALKTHROUGH.md` — 5분 시연 순서",
        "4. `03_PORTFOLIO_PITCH.md` — GitHub/면접용 소개 문구",
        "5. `demo_pack_manifest.json` — 산출물 목록과 SHA-256 무결성 정보",
    ]
    return "\n".join(lines)


def _demo_walkthrough(demo: dict[str, Any], scenarios: list[dict[str, Any]]) -> str:
    lines = [
        "# 5-Minute Demo Walkthrough",
        "",
        "## 0:00–0:40 Problem framing",
        "",
        "중소 조직은 사고가 의심돼도 Windows 로그를 수동으로 뒤져야 해서 초동 대응이 늦어집니다. BreachScope는 로그를 올리면 탐지, ATT&CK 매핑, IOC 후보, 케이스 패키지, 한글 보고서를 자동 생성합니다.",
        "",
        "## 0:40–1:30 Run the built-in scenario",
        "",
        "```bash",
        "python scripts/run.py --demo-scenario all --out out/demo/report --export-json --export-csv --pdf",
        "```",
        "",
        "## 1:30–2:40 Show the dashboard/report",
        "",
        f"이번 데모는 합성 이벤트 **{demo['total_events']}개**에서 탐지 **{demo['total_findings']}건**, 리스크 **{demo['risk_score']}/100 ({demo['risk_level']})**를 생성합니다.",
        "",
        "강조할 화면:",
        "",
        "- Risk Score / Executive Summary",
        "- Top Findings",
        "- Incident Timeline",
        "- ATT&CK tactic coverage",
        "- IOC CSV / case ZIP download",
        "- Korean PDF report",
        "",
        "## 2:40–3:40 Explain the sample scenarios",
        "",
    ]
    lines.extend(_md_table(["Scenario", "Events", "Expected ATT&CK"], ([row.get("id"), row.get("events"), ", ".join(row.get("expected_techniques", []))] for row in scenarios)))
    lines.extend([
        "",
        "## 3:40–4:30 Explain operational features",
        "",
        "- 관리자 로그인/HttpOnly 세션과 API Key 병행 지원",
        "- 케이스 이력, 담당자/상태/메모/종결 요약 관리",
        "- 감사 로그 JSONL/CSV export와 무결성 해시",
        "- 백업, 케이스 보존정리, 헬스체크, 메트릭, 셀프테스트",
        "- CI/CD, Docker smoke test, 릴리즈 checksum/manifest",
        "",
        "## 4:30–5:00 Close",
        "",
        "단순 로그 검색기가 아니라, 내부 보안팀/컨설턴트가 사고 초동분석 결과를 관리하고 납품물로 내보내는 DFIR 운영 콘솔이라는 점을 강조합니다.",
    ])
    return "\n".join(lines)


def _portfolio_pitch(demo: dict[str, Any]) -> str:
    return "\n".join([
        "# Portfolio Pitch",
        "",
        "## One-liner",
        "",
        "BreachScope는 Windows 이벤트 로그를 분석해 ATT&CK 탐지, IOC 추출, 사고 타임라인, 케이스 워크플로, 한글 PDF 보고서까지 자동 생성하는 제품형 DFIR 콘솔입니다.",
        "",
        "## 30-second pitch",
        "",
        f"BreachScope는 사고 의심 로그를 업로드하면 룰팩 **{demo['rule_count']}개**로 탐지하고, 리스크 점수, ATT&CK 커버리지, IOC 후보, 타임라인, 우선 조치 권고를 자동 생성합니다. 또한 케이스 이력, 담당자/상태/메모, 감사 로그, 백업, 헬스체크, 메트릭, CI/CD, Docker 배포까지 갖춰 단순 스크립트가 아니라 운영 가능한 내부 DFIR 콘솔 형태로 구현했습니다.",
        "",
        "## Interview bullets",
        "",
        "- 탐지 정확도뿐 아니라 대응자가 바로 쓰는 산출물 중심으로 설계했습니다.",
        "- MITRE ATT&CK 기준으로 룰팩 커버리지와 사고 단계를 설명할 수 있게 만들었습니다.",
        "- 보안 제품답게 인증, 감사 로그, 무결성 해시, 백업, 품질 게이트를 넣었습니다.",
        "- GitHub Actions와 릴리즈 manifest/checksum까지 넣어 공개 가능한 프로젝트 형태로 마감했습니다.",
    ])


def _github_upload_checklist() -> str:
    return "\n".join([
        "# GitHub Upload Checklist",
        "",
        "## Before push",
        "",
        "- [ ] `python scripts/quality_gate.py --strict` 통과",
        "- [ ] `python scripts/project_check.py --strict` 통과",
        "- [ ] `.env` 파일이 커밋되지 않았는지 확인",
        "- [ ] `dist/`, `out/`, `*.jsonl`, `*.db`, `*.log`가 커밋되지 않았는지 확인",
        "- [ ] README 첫 문단과 데모 명령 확인",
        "",
        "## First release",
        "",
        "```bash",
        "python scripts/build_release.py --clean",
        "git tag v1.0.0",
        "git push origin v1.0.0",
        "```",
        "",
        "## First production run",
        "",
        "```bash",
        "python scripts/init_env.py --production --https --output .env",
        "python scripts/go_live_check.py --deployment-mode production",
        "docker compose up --build",
        "```",
    ])


def _release_notes(meta: dict[str, Any], demo: dict[str, Any]) -> str:
    return "\n".join([
        f"# BreachScope {meta.get('version', '')} Demo Release Notes",
        "",
        "## Highlights",
        "",
        "- Product-style DFIR web console with CLI and API workflows",
        "- 50-rule ATT&CK-aligned Windows detection rulepack",
        "- 10 safe synthetic incident scenarios for demonstrations",
        "- IOC CSV, rule catalog CSV, manifest, case ZIP, and Korean PDF report outputs",
        "- Case history, workflow status, assignee, notes, and closure summary",
        "- Authentication, audit trail, backups, retention pruning, health checks, metrics, and self-test",
        "- GitHub Actions CI/CD, Docker smoke test workflow, release checksums, quality gate, and go-live readiness checks",
        "",
        "## Demo output",
        "",
        f"- Events: {demo['total_events']}",
        f"- Findings: {demo['total_findings']}",
        f"- Risk: {demo['risk_score']}/100 ({demo['risk_level']})",
        f"- Rulepack: {demo['rule_count']} rules / {demo['rule_techniques']} ATT&CK techniques",
    ])


def _screenshot_guide() -> str:
    return "\n".join([
        "# Screenshot Guide",
        "",
        "Use this checklist to capture GitHub README images or a portfolio slide.",
        "",
        "## Recommended screenshots",
        "",
        "1. Web dashboard after running `--demo-scenario all`",
        "2. Risk Score + Executive Summary card",
        "3. Top Findings tab",
        "4. Incident Timeline tab",
        "5. ATT&CK coverage / host risk section",
        "6. Korean PDF first page",
        "7. Case history/workflow panel",
        "8. Quality Gate and Go-Live readiness screens",
        "",
        "## Suggested README caption",
        "",
        "> Synthetic demo data only. BreachScope does not ship real customer logs or weaponized payloads.",
    ])


def _artifact(path: Path, root: Path, purpose: str) -> DemoPackArtifact:
    return DemoPackArtifact(
        path=path.relative_to(root).as_posix(),
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
        purpose=purpose,
    )


def _write_checksums(output_dir: Path, artifacts: list[DemoPackArtifact]) -> None:
    lines = [f"{artifact.sha256}  {artifact.path}" for artifact in sorted(artifacts, key=lambda item: item.path)]
    _write_file(output_dir / "SHA256SUMS.txt", "\n".join(lines))


def _zip_demo_pack(output_dir: Path, zip_name: str = "breachscope-demo-pack.zip") -> Path:
    zip_path = output_dir / zip_name
    if zip_path.exists():
        zip_path.unlink()
    with ZipFile(zip_path, "w", ZIP_DEFLATED) as zf:
        for path in sorted(output_dir.rglob("*")):
            if not path.is_file() or path == zip_path:
                continue
            zf.write(path, f"breachscope-demo-pack/{path.relative_to(output_dir).as_posix()}")
    return zip_path


def build_demo_pack(
    repo_root: str | Path = ".",
    output_dir: str | Path | None = None,
    *,
    clean: bool = False,
    render_pdf: bool = True,
) -> dict[str, Any]:
    """Build a shareable demo/handoff package.

    The package is intentionally generated into an output directory so it is
    excluded from source releases by the existing ``out/*`` release hygiene.
    """
    root = Path(repo_root).resolve()
    out = Path(output_dir).resolve() if output_dir else root / "out" / "demo_pack"
    if clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    reports_dir = out / "reports"
    samples_dir = out / "samples" / "scenarios"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_all_demo_scenarios(samples_dir)

    report_prefix = reports_dir / "breachscope_demo_report"
    with _pushd(root):
        run_pipeline(
            input_dir=root / "samples" / "scenarios",
            rules_dir=root / "rules",
            out_prefix=report_prefix,
            export_json_flag=True,
            export_csv_flag=True,
            render_pdf=render_pdf,
        )

    report_json = _read_json(report_prefix.with_suffix(".json"))
    demo = _safe_summary(report_json)
    meta = asdict(get_project_metadata(root))
    readiness = run_project_readiness(root)
    quality = run_quality_gate(root)
    scenarios = list_demo_scenarios()
    # JSON exports intentionally omit full event bodies in some modes; use the
    # built-in scenario catalog as the authoritative demo event count.
    demo["total_events"] = sum(int(row.get("events", 0)) for row in scenarios)

    _write_file(out / "README.md", _executive_overview(meta, demo, readiness, quality))
    _write_file(out / "02_DEMO_WALKTHROUGH.md", _demo_walkthrough(demo, scenarios))
    _write_file(out / "03_PORTFOLIO_PITCH.md", _portfolio_pitch(demo))
    _write_file(out / "04_RELEASE_NOTES.md", _release_notes(meta, demo))
    _write_file(out / "05_GITHUB_UPLOAD_CHECKLIST.md", _github_upload_checklist())
    _write_file(out / "06_SCREENSHOT_GUIDE.md", _screenshot_guide())

    rules = load_rules(root / "rules")
    rule_summary = summarize_rules(rules)
    manifest = {
        "generated_at": _utc_now_iso(),
        "metadata": meta,
        "demo_summary": demo,
        "rulepack": rule_summary,
        "project_readiness": {"status": readiness.get("status"), "score": readiness.get("score"), "summary": readiness.get("summary")},
        "quality_gate": {"status": quality.get("status"), "score": quality.get("score"), "summary": quality.get("summary")},
        "entrypoints": {
            "html_report": "reports/breachscope_demo_report.html",
            "pdf_report": "reports/breachscope_demo_report.pdf" if report_prefix.with_suffix(".pdf").exists() else None,
            "walkthrough": "02_DEMO_WALKTHROUGH.md",
            "portfolio_pitch": "03_PORTFOLIO_PITCH.md",
        },
    }
    (out / "demo_pack_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    artifacts: list[DemoPackArtifact] = []
    purposes = {
        "README.md": "Executive overview and open-first guide",
        "02_DEMO_WALKTHROUGH.md": "5-minute demo script",
        "03_PORTFOLIO_PITCH.md": "Portfolio/interview pitch",
        "04_RELEASE_NOTES.md": "Public release highlights",
        "05_GITHUB_UPLOAD_CHECKLIST.md": "GitHub and production first-run checklist",
        "06_SCREENSHOT_GUIDE.md": "Suggested screenshots for README/portfolio",
        "demo_pack_manifest.json": "Structured demo-pack manifest",
        "reports/breachscope_demo_report.html": "Full HTML analysis report",
        "reports/breachscope_demo_report.pdf": "Korean PDF report",
        "reports/breachscope_demo_report.json": "Structured analysis report",
        "reports/breachscope_demo_report.csv": "Finding export CSV",
        "reports/breachscope_demo_report.iocs.csv": "IOC candidate export CSV",
        "reports/breachscope_demo_report.rules.csv": "Rule catalog CSV",
        "reports/breachscope_demo_report.manifest.json": "Evidence/report artifact manifest",
        "reports/breachscope_demo_report.zip": "Case package ZIP",
    }
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name not in {"SHA256SUMS.txt", "breachscope-demo-pack.zip"}:
            rel = path.relative_to(out).as_posix()
            artifacts.append(_artifact(path, out, purposes.get(rel, "Demo-pack file")))

    _write_checksums(out, artifacts)
    artifacts.append(_artifact(out / "SHA256SUMS.txt", out, "SHA-256 checksums for demo-pack files"))

    zip_path = _zip_demo_pack(out)
    zip_artifact = _artifact(zip_path, out, "Shareable demo-pack ZIP")

    result = {
        "success": True,
        "output_dir": str(out),
        "zip_path": str(zip_path),
        "zip_sha256": zip_artifact.sha256,
        "demo_summary": demo,
        "project_readiness": {"status": readiness.get("status"), "score": readiness.get("score")},
        "quality_gate": {"status": quality.get("status"), "score": quality.get("score")},
        "artifacts": [asdict(item) for item in artifacts] + [asdict(zip_artifact)],
    }
    (out / "demo_pack_result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


__all__ = ["build_demo_pack"]
