"""Static showcase/landing-page builder for BreachScope.

The demo pack is meant to be downloaded and reviewed offline. The showcase is
meant to be published as a tiny static site, for example with GitHub Pages, so a
reviewer can understand the project before cloning it.
"""
from __future__ import annotations

import html
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
class ShowcaseArtifact:
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


def _write_text(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.rstrip() + "\n", encoding="utf-8")


def _safe_report_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    risk = summary.get("risk") or {}
    rule_pack = summary.get("rule_pack") or {}
    indicator_totals = summary.get("indicator_totals") or {}
    sample_scenarios = summary.get("sample_scenarios") or []
    host_risk = summary.get("host_risk_summary") or []
    attack_coverage = summary.get("attack_coverage") or []
    event_count = len(report.get("events", [])) if isinstance(report, dict) and isinstance(report.get("events"), list) else 0
    if not event_count and isinstance(sample_scenarios, list):
        event_count = sum(int(row.get("events", 0) or 0) for row in sample_scenarios if isinstance(row, dict))
    return {
        "events": event_count,
        "findings": int(summary.get("total_findings") or 0),
        "risk_score": int(risk.get("score") or 0),
        "risk_level": str(risk.get("level") or "none"),
        "affected_hosts": int(risk.get("unique_hosts") or len(host_risk) or 0),
        "finding_techniques": int(risk.get("unique_techniques") or 0),
        "rule_count": int(rule_pack.get("total_rules") or 0),
        "rule_techniques": int(rule_pack.get("unique_techniques") or 0),
        "rule_coverage": float(rule_pack.get("coverage_percent_core_windows") or 0.0),
        "scenario_count": len(sample_scenarios),
        "indicator_totals": indicator_totals,
        "top_hosts": host_risk[:5],
        "top_tactics": attack_coverage[:6],
    }


def _copy_report_artifacts(source_prefix: Path, reports_dir: Path) -> list[Path]:
    copied: list[Path] = []
    for suffix in [".html", ".json", ".csv", ".iocs.csv", ".rules.csv", ".manifest.json", ".zip", ".pdf"]:
        src = source_prefix.with_suffix(suffix)
        if not src.exists():
            continue
        dst = reports_dir / f"breachscope_showcase_report{suffix}"
        shutil.copy2(src, dst)
        copied.append(dst)
    return copied


def _artifact(path: Path, root: Path, purpose: str) -> ShowcaseArtifact:
    return ShowcaseArtifact(
        path=path.relative_to(root).as_posix(),
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
        purpose=purpose,
    )


def _write_checksums(root: Path, artifacts: Iterable[ShowcaseArtifact]) -> None:
    lines = [f"{a.sha256}  {a.path}" for a in sorted(artifacts, key=lambda x: x.path)]
    _write_text(root / "SHA256SUMS.txt", "\n".join(lines))


def _social_preview_svg(meta: dict[str, Any], demo: dict[str, Any]) -> str:
    title = html.escape(str(meta.get("name") or "BreachScope"))
    subtitle = "DFIR Console · ATT&CK · IOC · Korean PDF"
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="{title} showcase preview">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0f172a"/><stop offset="1" stop-color="#172554"/></linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="18" stdDeviation="20" flood-color="#000" flood-opacity=".35"/></filter>
  </defs>
  <rect width="1200" height="630" rx="36" fill="url(#bg)"/>
  <circle cx="1040" cy="120" r="180" fill="#38bdf8" opacity=".18"/>
  <circle cx="140" cy="560" r="220" fill="#22c55e" opacity=".12"/>
  <g filter="url(#shadow)">
    <rect x="76" y="78" width="1048" height="474" rx="30" fill="#020617" opacity=".78" stroke="#334155"/>
    <text x="120" y="165" fill="#e2e8f0" font-family="Arial, sans-serif" font-size="70" font-weight="700">{title}</text>
    <text x="124" y="220" fill="#93c5fd" font-family="Arial, sans-serif" font-size="30">{subtitle}</text>
    <text x="124" y="304" fill="#f8fafc" font-family="Arial, sans-serif" font-size="38" font-weight="700">{demo['findings']} findings · Risk {demo['risk_score']}/100 · {demo['rule_count']} rules</text>
    <text x="124" y="358" fill="#cbd5e1" font-family="Arial, sans-serif" font-size="28">10 safe demo scenarios · {demo['rule_coverage']}% core Windows ATT&amp;CK coverage</text>
    <g transform="translate(124 420)">
      <rect width="190" height="62" rx="18" fill="#1d4ed8"/><text x="28" y="40" fill="#fff" font-family="Arial, sans-serif" font-size="23" font-weight="700">Web Console</text>
      <rect x="214" width="170" height="62" rx="18" fill="#166534"/><text x="248" y="40" fill="#fff" font-family="Arial, sans-serif" font-size="23" font-weight="700">IOC CSV</text>
      <rect x="408" width="210" height="62" rx="18" fill="#7c2d12"/><text x="438" y="40" fill="#fff" font-family="Arial, sans-serif" font-size="23" font-weight="700">Korean PDF</text>
      <rect x="642" width="180" height="62" rx="18" fill="#581c87"/><text x="681" y="40" fill="#fff" font-family="Arial, sans-serif" font-size="23" font-weight="700">CI/CD</text>
    </g>
  </g>
</svg>'''


def _index_html(meta: dict[str, Any], demo: dict[str, Any], readiness: dict[str, Any], quality: dict[str, Any], scenarios: list[dict[str, Any]]) -> str:
    def esc(value: object) -> str:
        return html.escape(str(value))

    cards = [
        ("Risk Score", f"{demo['risk_score']}/100", demo["risk_level"]),
        ("Findings", demo["findings"], f"{demo['events']} demo events"),
        ("Rulepack", demo["rule_count"], f"{demo['rule_techniques']} ATT&CK techniques"),
        ("Coverage", f"{demo['rule_coverage']}%", "Core Windows techniques"),
        ("Scenarios", demo["scenario_count"], "safe synthetic logs"),
        ("Quality", f"{quality.get('score', 0)}/100", f"readiness {readiness.get('score', 0)}/100"),
    ]
    card_html = "\n".join(
        f'<article class="metric"><span>{esc(k)}</span><strong>{esc(v)}</strong><small>{esc(s)}</small></article>'
        for k, v, s in cards
    )
    scenario_html = "\n".join(
        f'<li><b>{esc(row.get("id", ""))}</b><span>{esc(row.get("events", 0))} events · {esc(", ".join(row.get("expected_techniques", [])))}</span></li>'
        for row in scenarios
    )
    tactics = demo.get("top_tactics") or []
    tactic_html = "\n".join(
        f'<li><b>{esc(row.get("tactic", "unknown"))}</b><span>{esc(row.get("count", 0))} findings</span></li>'
        for row in tactics
    ) or "<li><b>No findings</b><span>Run the demo scenario first.</span></li>"
    return f'''<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BreachScope Showcase</title>
  <meta name="description" content="BreachScope static portfolio showcase for a product-style DFIR console." />
  <meta property="og:title" content="BreachScope DFIR Console" />
  <meta property="og:description" content="ATT&CK detection, IOC extraction, case workflow, Korean PDF reporting, and operational controls." />
  <meta property="og:image" content="assets/social-preview.svg" />
  <link rel="stylesheet" href="assets/showcase.css" />
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">Static showcase · generated {esc(meta.get('generated_at', ''))}</p>
      <h1>BreachScope</h1>
      <p class="lead">Windows 로그를 분석해 ATT&CK 탐지, IOC 후보, 사고 타임라인, 케이스 워크플로, 한글 PDF 보고서까지 생성하는 제품형 DFIR 콘솔입니다.</p>
      <div class="actions">
        <a href="reports/breachscope_showcase_report.html">HTML 리포트 열기</a>
        <a href="reports/breachscope_showcase_report.pdf">PDF 리포트 열기</a>
        <a href="data/showcase_summary.json">요약 JSON</a>
      </div>
    </section>

    <section class="grid metrics">{card_html}</section>

    <section class="grid two">
      <article class="panel">
        <h2>What it proves</h2>
        <ul class="feature-list">
          <li>50개 룰팩과 ATT&CK 전술/기법 커버리지</li>
          <li>IOC CSV, 룰 카탈로그, manifest, case ZIP 산출물</li>
          <li>케이스 이력, 담당자, 상태, 분석 메모, 종결 요약</li>
          <li>인증, 감사 로그, 백업, 헬스체크, 메트릭, 셀프테스트</li>
          <li>CI/CD, Docker smoke test, 릴리즈 checksum/manifest</li>
        </ul>
      </article>
      <article class="panel">
        <h2>Top ATT&CK tactics in demo</h2>
        <ul class="split-list">{tactic_html}</ul>
      </article>
    </section>

    <section class="panel">
      <h2>Safe built-in demo scenarios</h2>
      <p>시연 데이터는 실제 악성코드가 아니라 합성 JSONL 로그입니다. 외부 공유와 면접 시연에 안전하게 사용할 수 있습니다.</p>
      <ul class="scenario-list">{scenario_html}</ul>
    </section>

    <section class="grid two">
      <article class="panel">
        <h2>Run locally</h2>
        <pre><code>python scripts/run.py --demo-scenario all --out out/report --export-json --export-csv --pdf
uvicorn api.main:app --host 127.0.0.1 --port 8000</code></pre>
      </article>
      <article class="panel">
        <h2>Publish this showcase</h2>
        <pre><code>python scripts/build_showcase.py --clean
# publish out/showcase to GitHub Pages or attach out/showcase/breachscope-showcase.zip</code></pre>
      </article>
    </section>

    <footer>
      <span>Version {esc(meta.get('version', 'unknown'))}</span>
      <span>Project readiness {esc(readiness.get('score', 0))}/100</span>
      <span>Quality gate {esc(quality.get('score', 0))}/100</span>
    </footer>
  </main>
</body>
</html>'''


def _css() -> str:
    return '''*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#020617;color:#e2e8f0;line-height:1.6}.shell{width:min(1120px,92vw);margin:0 auto;padding:52px 0}.hero{padding:56px;border:1px solid #1e293b;border-radius:34px;background:radial-gradient(circle at top right,rgba(56,189,248,.22),transparent 32%),linear-gradient(135deg,#0f172a,#111827);box-shadow:0 24px 80px rgba(0,0,0,.36)}.eyebrow{text-transform:uppercase;letter-spacing:.14em;color:#93c5fd;font-size:13px;font-weight:800}.hero h1{font-size:72px;line-height:1;margin:10px 0 18px}.lead{font-size:22px;max-width:860px;color:#cbd5e1}.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:28px}.actions a{color:white;text-decoration:none;background:#2563eb;border:1px solid #60a5fa;padding:13px 18px;border-radius:14px;font-weight:800}.grid{display:grid;gap:18px}.metrics{grid-template-columns:repeat(6,1fr);margin:22px 0}.metric,.panel{border:1px solid #1e293b;background:#0f172a;border-radius:24px;padding:22px}.metric span,.metric small{display:block;color:#94a3b8}.metric strong{display:block;font-size:34px;color:#f8fafc;margin:6px 0}.two{grid-template-columns:1fr 1fr;margin:18px 0}.panel h2{margin-top:0;color:#f8fafc}.feature-list,.split-list,.scenario-list{padding:0;margin:0;list-style:none}.feature-list li{padding:9px 0;border-bottom:1px solid #1e293b}.split-list li,.scenario-list li{display:flex;justify-content:space-between;gap:20px;padding:12px 0;border-bottom:1px solid #1e293b}.split-list span,.scenario-list span{color:#94a3b8;text-align:right}pre{white-space:pre-wrap;background:#020617;border:1px solid #334155;border-radius:16px;padding:16px;overflow:auto;color:#bfdbfe}footer{display:flex;gap:14px;flex-wrap:wrap;color:#94a3b8;margin-top:22px}footer span{border:1px solid #1e293b;border-radius:999px;padding:8px 12px}@media(max-width:900px){.metrics,.two{grid-template-columns:1fr}.hero{padding:32px}.hero h1{font-size:48px}.lead{font-size:18px}}'''


def _readme(meta: dict[str, Any], demo: dict[str, Any]) -> str:
    return f"""# BreachScope Static Showcase

This folder is a static, GitHub-Pages-ready showcase for BreachScope.

## Open first

1. `index.html` — landing page for reviewers
2. `reports/breachscope_showcase_report.html` — full HTML demo report
3. `reports/breachscope_showcase_report.pdf` — Korean PDF report
4. `data/showcase_summary.json` — machine-readable metrics
5. `SHA256SUMS.txt` — artifact integrity checksums

## Snapshot

- Version: `{meta.get('version', 'unknown')}`
- Demo events: **{demo['events']}**
- Findings: **{demo['findings']}**
- Risk: **{demo['risk_score']}/100 ({demo['risk_level']})**
- Rulepack: **{demo['rule_count']} rules / {demo['rule_techniques']} techniques / {demo['rule_coverage']}% coverage**

## Regenerate

```bash
python scripts/build_showcase.py --clean
```
"""


def build_showcase(
    repo_root: str | Path = ".",
    out_dir: str | Path = "out/showcase",
    *,
    clean: bool = False,
    render_pdf: bool = True,
) -> dict[str, Any]:
    """Build a static showcase folder and ZIP archive."""
    root = Path(repo_root).resolve()
    out = Path(out_dir).resolve()
    if clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    scenarios_dir = out / "_scenario_inputs"
    reports_dir = out / "reports"
    data_dir = out / "data"
    assets_dir = out / "assets"
    reports_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    assets_dir.mkdir(parents=True, exist_ok=True)

    with _pushd(root):
        write_all_demo_scenarios(scenarios_dir)
        source_prefix = out / "_generated" / "breachscope_showcase_report"
        run_pipeline(
            input_dir=scenarios_dir,
            rules_dir=root / "rules",
            out_prefix=source_prefix,
            export_json_flag=True,
            export_csv_flag=True,
            render_pdf=render_pdf,
        )
        report_json = source_prefix.with_suffix(".json")
        report = _read_json(report_json)
        demo = _safe_report_summary(report)
        rules = load_rules(root / "rules")
        rulepack = summarize_rules(rules)
        if not demo["rule_count"]:
            demo["rule_count"] = int(rulepack.get("total_rules") or len(rules))
            demo["rule_techniques"] = int(rulepack.get("unique_techniques") or 0)
            demo["rule_coverage"] = float(rulepack.get("coverage_percent_core_windows") or 0.0)
        readiness = run_project_readiness(root)
        quality = run_quality_gate(root)
        scenarios = list_demo_scenarios()
        copied_reports = _copy_report_artifacts(source_prefix, reports_dir)

    meta_obj = get_project_metadata(root)
    meta = asdict(meta_obj)
    meta["generated_at"] = _utc_now_iso()

    summary = {
        "success": True,
        "kind": "breachscope_static_showcase",
        "generated_at": meta["generated_at"],
        "metadata": meta,
        "demo_summary": demo,
        "project_readiness": {"status": readiness.get("status"), "score": readiness.get("score")},
        "quality_gate": {"status": quality.get("status"), "score": quality.get("score")},
        "scenarios": scenarios,
    }
    _write_text(data_dir / "showcase_summary.json", json.dumps(summary, ensure_ascii=False, indent=2))
    _write_text(assets_dir / "showcase.css", _css())
    _write_text(assets_dir / "social-preview.svg", _social_preview_svg(meta, demo))
    _write_text(out / "index.html", _index_html(meta, demo, readiness, quality, scenarios))
    _write_text(out / "README.md", _readme(meta, demo))

    artifacts: list[ShowcaseArtifact] = []
    purposes = {
        "index.html": "static showcase landing page",
        "README.md": "showcase usage notes",
        "data/showcase_summary.json": "machine-readable demo and readiness metrics",
        "assets/showcase.css": "landing page styles",
        "assets/social-preview.svg": "social preview/README image asset",
    }
    for rel, purpose in purposes.items():
        p = out / rel
        if p.exists():
            artifacts.append(_artifact(p, out, purpose))
    for p in copied_reports:
        purpose = "generated demo report artifact"
        artifacts.append(_artifact(p, out, purpose))

    manifest = {
        **summary,
        "artifacts": [asdict(a) for a in artifacts],
    }
    _write_text(out / "showcase_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    artifacts.append(_artifact(out / "showcase_manifest.json", out, "artifact manifest with SHA-256 metadata"))
    _write_checksums(out, artifacts)
    artifacts.append(_artifact(out / "SHA256SUMS.txt", out, "checksum list"))

    zip_path = out / "breachscope-showcase.zip"
    if zip_path.exists():
        zip_path.unlink()
    with ZipFile(zip_path, "w", ZIP_DEFLATED) as zf:
        for artifact in artifacts:
            zf.write(out / artifact.path, f"breachscope-showcase/{artifact.path}")
    zip_artifact = _artifact(zip_path, out, "shareable static showcase archive")

    result = {
        **summary,
        "output_dir": str(out),
        "zip_path": str(zip_path),
        "zip_sha256": zip_artifact.sha256,
        "artifacts": [asdict(a) for a in artifacts] + [asdict(zip_artifact)],
    }
    _write_text(out / "showcase_result.json", json.dumps(result, ensure_ascii=False, indent=2))
    return result
