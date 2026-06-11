"""Repository and product-readiness checks for BreachScope.

The checks are intentionally lightweight and deterministic so they can be used
from the CLI, the web operations API, and GitHub Actions without running the
full test suite. They answer a simple release-manager question: "does this
checkout look ready to publish or demo?"
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from breachscope.demo_scenarios import list_demo_scenarios
from breachscope.rulepack import summarize_rules
from breachscope.rules import load_rules
from breachscope.quality_gate import run_quality_gate


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    status: str
    message: str
    details: dict[str, Any]

    @property
    def passed(self) -> bool:
        return self.status == "pass"


def _exists_check(root: Path, name: str, paths: list[str], message: str) -> ReadinessCheck:
    missing = [path for path in paths if not (root / path).exists()]
    return ReadinessCheck(
        name=name,
        status="pass" if not missing else "fail",
        message=message if not missing else f"Missing {len(missing)} required path(s).",
        details={"required": paths, "missing": missing},
    )


def _contains_check(root: Path, name: str, path: str, needles: list[str], message: str) -> ReadinessCheck:
    target = root / path
    if not target.exists():
        return ReadinessCheck(name=name, status="fail", message=f"{path} does not exist.", details={"missing": [path]})
    text = target.read_text(encoding="utf-8", errors="ignore").lower()
    missing = [needle for needle in needles if needle.lower() not in text]
    return ReadinessCheck(
        name=name,
        status="pass" if not missing else "warn",
        message=message if not missing else f"{path} is present but missing some recommended wording.",
        details={"file": path, "expected_terms": needles, "missing_terms": missing},
    )


def _rulepack_check(root: Path) -> ReadinessCheck:
    try:
        rules = load_rules(root / "rules")
        summary = summarize_rules(rules)
        total = int(summary.get("total_rules", len(rules)))
        unique = int(summary.get("unique_techniques", 0))
        coverage = float(summary.get("coverage_percent_core_windows", 0.0))
        ok = total >= 50 and unique >= 35 and coverage >= 80
        return ReadinessCheck(
            name="rulepack_coverage",
            status="pass" if ok else "warn",
            message=(
                f"Rulepack has {total} rules, {unique} ATT&CK techniques, "
                f"{coverage}% core Windows coverage."
            ),
            details={"rules": total, "unique_techniques": unique, "coverage_percent_core_windows": coverage},
        )
    except Exception as exc:  # pragma: no cover - defensive for broken checkouts
        return ReadinessCheck(
            name="rulepack_coverage",
            status="fail",
            message=f"Rulepack failed to load: {exc}",
            details={"error": str(exc)},
        )


def _scenario_check() -> ReadinessCheck:
    try:
        scenarios = list_demo_scenarios()
        count = len(scenarios)
        event_count = sum(int(row.get("events", 0)) for row in scenarios)
        ok = count >= 10 and event_count >= 40
        return ReadinessCheck(
            name="demo_scenarios",
            status="pass" if ok else "warn",
            message=f"Built-in demo set has {count} scenarios and {event_count} events.",
            details={"scenarios": count, "events": event_count, "ids": [row.get("id") for row in scenarios]},
        )
    except Exception as exc:  # pragma: no cover
        return ReadinessCheck(
            name="demo_scenarios",
            status="fail",
            message=f"Demo scenarios failed to load: {exc}",
            details={"error": str(exc)},
        )


def _count_files(root: Path, pattern: str) -> int:
    return sum(1 for path in root.glob(pattern) if path.is_file())


def run_project_readiness(root: str | Path = ".") -> dict[str, Any]:
    """Run a lightweight repository/product readiness review."""
    root_path = Path(root).resolve()
    checks: list[ReadinessCheck] = [
        _exists_check(
            root_path,
            "core_project_files",
            ["README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE", "pyproject.toml", "requirements.txt"],
            "Core project metadata and governance files are present.",
        ),
        _exists_check(
            root_path,
            "operator_docs",
            [
                "docs/QUICKSTART.md",
                "docs/DEPLOYMENT.md",
                "docs/API_DOCUMENTATION.md",
                "docs/CASE_WORKFLOW.md",
                "docs/CI_CD.md",
                "docs/RELEASE.md",
                "docs/QUALITY_GATE.md",
                "docs/GO_LIVE.md",
                "docs/DEMO_PACK.md",
                "docs/PUBLISH_PREP.md",
            ],
            "Operator, deployment, API, workflow, CI/CD, release, quality gate, go-live, demo-pack, and publish-prep docs are present.",
        ),
        _exists_check(
            root_path,
            "github_automation",
            [".github/workflows/ci.yml", ".github/workflows/docker.yml", ".github/workflows/release.yml"],
            "GitHub Actions workflows are present.",
        ),
        _exists_check(
            root_path,
            "github_collaboration_templates",
            [
                ".github/ISSUE_TEMPLATE/bug_report.yml",
                ".github/ISSUE_TEMPLATE/feature_request.yml",
                ".github/pull_request_template.md",
            ],
            "Issue and pull request templates are present.",
        ),
        _exists_check(
            root_path,
            "container_deployment",
            ["Dockerfile", "docker-compose.yml", ".dockerignore", ".env.example"],
            "Docker deployment files are present.",
        ),
        _contains_check(
            root_path,
            "readme_product_positioning",
            "README.md",
            ["DFIR", "Docker", "감사 로그", "한글 PDF", "CI/CD", "Go-Live"],
            "README covers product positioning, operations, reporting, and automation.",
        ),
        _contains_check(
            root_path,
            "env_security_defaults",
            ".env.example",
            ["BS_API_KEY", "BS_ADMIN_PASSWORD", "BS_SESSION_SECRET", "BS_AUDIT_LOG_PATH", "BS_BACKUP_ROOT", "BS_DEPLOYMENT_MODE"],
            ".env.example documents deployment security and data paths.",
        ),
        _exists_check(
            root_path,
            "quality_gate_tooling",
            ["scripts/quality_gate.py", "breachscope/quality_gate.py", "docs/QUALITY_GATE.md"],
            "Quality/security gate tooling and documentation are present.",
        ),
        _exists_check(
            root_path,
            "go_live_tooling",
            ["scripts/init_env.py", "scripts/go_live_check.py", "breachscope/golive.py", "docs/GO_LIVE.md"],
            "First-run secret generation and go-live readiness tooling are present.",
        ),
        _exists_check(
            root_path,
            "demo_pack_tooling",
            ["scripts/build_demo_pack.py", "breachscope/demo_pack.py", "docs/DEMO_PACK.md"],
            "Shareable demo/handoff pack tooling and documentation are present.",
        ),
        _exists_check(
            root_path,
            "publish_prep_tooling",
            ["scripts/publish_prep.py", "breachscope/publish.py", "docs/PUBLISH_PREP.md"],
            "Final public-launch publish-prep tooling and documentation are present.",
        ),
        _rulepack_check(root_path),
        _scenario_check(),
    ]


    try:
        quality = run_quality_gate(root_path)
        checks.append(
            ReadinessCheck(
                name="quality_gate",
                status="pass" if quality.get("status") == "pass" else "warn" if quality.get("status") == "warn" else "fail",
                message=f"Quality gate status is {quality.get('status')} with score {quality.get('score')}/100.",
                details={"score": quality.get("score"), "summary": quality.get("summary")},
            )
        )
    except Exception as exc:  # pragma: no cover
        checks.append(
            ReadinessCheck(
                name="quality_gate",
                status="fail",
                message=f"Quality gate failed to run: {exc}",
                details={"error": str(exc)},
            )
        )

    test_count = _count_files(root_path, "tests/test_*.py")
    checks.append(
        ReadinessCheck(
            name="test_suite_size",
            status="pass" if test_count >= 12 else "warn",
            message=f"Test suite contains {test_count} test module(s).",
            details={"test_modules": test_count},
        )
    )

    doc_count = _count_files(root_path, "docs/*.md")
    checks.append(
        ReadinessCheck(
            name="documentation_depth",
            status="pass" if doc_count >= 12 else "warn",
            message=f"Documentation folder contains {doc_count} markdown document(s).",
            details={"markdown_docs": doc_count},
        )
    )

    pass_count = sum(1 for check in checks if check.status == "pass")
    warn_count = sum(1 for check in checks if check.status == "warn")
    fail_count = sum(1 for check in checks if check.status == "fail")
    # Warnings subtract half a point; failures subtract two points. Clamp to 0-100.
    score = max(0, min(100, round(100 * (pass_count + 0.5 * warn_count) / max(1, len(checks)) - fail_count * 10)))
    if fail_count:
        status = "fail"
    elif warn_count:
        status = "warn"
    else:
        status = "pass"

    return {
        "success": fail_count == 0,
        "status": status,
        "score": score,
        "summary": {
            "checks": len(checks),
            "passed": pass_count,
            "warnings": warn_count,
            "failed": fail_count,
        },
        "root": str(root_path),
        "checks": [asdict(check) for check in checks],
    }


def render_markdown(result: dict[str, Any]) -> str:
    """Render readiness results as a compact Markdown report."""
    lines = [
        "# BreachScope Project Readiness Report",
        "",
        f"- Status: **{result['status']}**",
        f"- Score: **{result['score']}/100**",
        f"- Root: `{result['root']}`",
        "",
        "| Check | Status | Message |",
        "|---|---:|---|",
    ]
    for check in result.get("checks", []):
        lines.append(f"| `{check['name']}` | {check['status']} | {check['message']} |")
    lines.append("")
    return "\n".join(lines)
