"""Operational diagnostics, metrics, and self-test API."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from api.services.audit_log import AuditLogService
from api.services.ops_status import config_diagnostics, metrics_snapshot, prometheus_metrics, run_self_test
from breachscope.release import runtime_build_info
from breachscope.project_readiness import run_project_readiness
from breachscope.quality_gate import run_quality_gate
from breachscope.golive import run_go_live_check
from breachscope.demo_scenarios import list_demo_scenarios
from breachscope.showcase import build_showcase
from breachscope.rulepack import summarize_rules
from breachscope.rules import load_rules
from pathlib import Path

router = APIRouter()


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    """Return Prometheus-style operational metrics."""
    return PlainTextResponse(prometheus_metrics(), media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/metrics.json", response_class=JSONResponse)
async def metrics_json():
    """Return operational metrics as JSON for the web console."""
    return {"success": True, "metrics": metrics_snapshot()}


@router.get("/ops/config-check", response_class=JSONResponse)
async def config_check():
    """Return deployment configuration diagnostics."""
    return {"success": True, **config_diagnostics()}


@router.post("/ops/self-test", response_class=JSONResponse)
async def self_test(request: Request, render_pdf: bool = Query(False)):
    """Run a synthetic end-to-end pipeline check without storing a case."""
    result = run_self_test(render_pdf=render_pdf)
    AuditLogService().record(
        "ops.self_test",
        request=request,
        status="success" if result.get("success") else "failure",
        details={
            "scenario": result.get("scenario"),
            "findings": result.get("findings"),
            "risk_score": result.get("risk_score"),
            "render_pdf": render_pdf,
            "elapsed_seconds": result.get("elapsed_seconds"),
        },
    )
    return result


@router.get("/ops/release-info", response_class=JSONResponse)
async def release_info():
    """Return build/release metadata for support and deployment verification."""
    return {"success": True, "release": runtime_build_info()}


@router.get("/ops/project-check", response_class=JSONResponse)
async def project_check():
    """Return lightweight repository/product readiness checks for release reviews."""
    return run_project_readiness(".")


@router.get("/ops/quality-gate", response_class=JSONResponse)
async def quality_gate():
    """Return pre-publication quality/security gate results."""
    return run_quality_gate(".")

@router.get("/ops/go-live", response_class=JSONResponse)
async def go_live_check(deployment_mode: str | None = Query(None, pattern="^(local|production)$")):
    """Return final first-deployment/go-live readiness checks."""
    return run_go_live_check(".", deployment_mode=deployment_mode)



@router.get("/ops/demo-pack-preview", response_class=JSONResponse)
async def demo_pack_preview():
    """Return a lightweight preview of the public demo/handoff package contents."""
    scenarios = list_demo_scenarios()
    rules = load_rules(Path("rules"))
    rulepack = summarize_rules(rules)
    return {
        "success": True,
        "demo_pack": {
            "recommended_command": "python scripts/build_demo_pack.py --clean",
            "default_output_dir": "out/demo_pack",
            "zip_name": "breachscope-demo-pack.zip",
            "included_documents": [
                "README.md",
                "02_DEMO_WALKTHROUGH.md",
                "03_PORTFOLIO_PITCH.md",
                "04_RELEASE_NOTES.md",
                "05_GITHUB_UPLOAD_CHECKLIST.md",
                "06_SCREENSHOT_GUIDE.md",
            ],
            "included_reports": [
                "reports/breachscope_demo_report.html",
                "reports/breachscope_demo_report.pdf",
                "reports/breachscope_demo_report.json",
                "reports/breachscope_demo_report.csv",
                "reports/breachscope_demo_report.iocs.csv",
                "reports/breachscope_demo_report.rules.csv",
                "reports/breachscope_demo_report.manifest.json",
                "reports/breachscope_demo_report.zip",
            ],
            "scenario_count": len(scenarios),
            "scenario_events": sum(int(row.get("events", 0)) for row in scenarios),
            "rule_count": rulepack.get("total_rules", len(rules)),
            "unique_techniques": rulepack.get("unique_techniques", 0),
            "coverage_percent_core_windows": rulepack.get("coverage_percent_core_windows", 0),
        },
    }


@router.get("/ops/showcase-preview", response_class=JSONResponse)
async def showcase_preview():
    """Return a lightweight preview of the static GitHub Pages showcase."""
    scenarios = list_demo_scenarios()
    rules = load_rules(Path("rules"))
    rulepack = summarize_rules(rules)
    return {
        "success": True,
        "showcase": {
            "recommended_command": "python scripts/build_showcase.py --clean",
            "default_output_dir": "out/showcase",
            "zip_name": "breachscope-showcase.zip",
            "entrypoint": "index.html",
            "included_assets": [
                "index.html",
                "assets/showcase.css",
                "assets/social-preview.svg",
                "data/showcase_summary.json",
                "reports/breachscope_showcase_report.html",
                "reports/breachscope_showcase_report.pdf",
                "showcase_manifest.json",
                "SHA256SUMS.txt",
            ],
            "scenario_count": len(scenarios),
            "scenario_events": sum(int(row.get("events", 0)) for row in scenarios),
            "rule_count": rulepack.get("total_rules", len(rules)),
            "unique_techniques": rulepack.get("unique_techniques", 0),
            "coverage_percent_core_windows": rulepack.get("coverage_percent_core_windows", 0),
        },
    }

@router.get("/ops/publish-prep-preview", response_class=JSONResponse)
async def publish_prep_preview():
    """Return a lightweight preview of the final public launch package."""
    scenarios = list_demo_scenarios()
    rules = load_rules(Path("rules"))
    rulepack = summarize_rules(rules)
    return {
        "success": True,
        "publish_prep": {
            "recommended_command": "python scripts/publish_prep.py --clean",
            "default_output_dir": "out/publish",
            "zip_name": "breachscope-public-launch-pack.zip",
            "included_sections": [
                "dist/ release ZIP, checksum, and manifest",
                "demo_pack/ external handoff package",
                "showcase/ GitHub Pages static landing package",
                "PUBLIC_LAUNCH_SUMMARY.md",
                "GITHUB_PUBLISH_COMMANDS.md",
                "RELEASE_NOTE_DRAFT.md",
                "publish_manifest.json",
                "SHA256SUMS.txt",
            ],
            "scenario_count": len(scenarios),
            "scenario_events": sum(int(row.get("events", 0)) for row in scenarios),
            "rule_count": rulepack.get("total_rules", len(rules)),
            "unique_techniques": rulepack.get("unique_techniques", 0),
            "coverage_percent_core_windows": rulepack.get("coverage_percent_core_windows", 0),
        },
    }

