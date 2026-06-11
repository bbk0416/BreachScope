"""Go-live readiness checks for first production deployments.

The project-readiness and quality-gate checks answer whether the repository is
safe to publish.  This module answers a different operator question: "is this
running configuration safe enough to expose to other users?"
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from api.services.audit_log import audit_is_enabled, audit_log_path
from api.services.backup_service import BackupService
from api.services.case_history import CaseHistoryService
from api.security import configured_admin_password, configured_api_key, session_ttl_seconds
from api.services.ops_status import _path_info  # lightweight helper already used by readiness checks
from breachscope.project_readiness import run_project_readiness
from breachscope.quality_gate import run_quality_gate

PLACEHOLDER_PREFIXES = ("change-me", "changeme", "example", "placeholder", "your-", "your_")
SECRET_ENV_KEYS = (
    "BS_API_KEY",
    "BS_ADMIN_PASSWORD",
    "BS_SESSION_SECRET",
    "BS_AUDIT_CHAIN_SECRET",
)


@dataclass(frozen=True)
class GoLiveCheck:
    name: str
    status: str
    message: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _env_bool(env: Mapping[str, str], name: str, default: str = "0") -> bool:
    return str(env.get(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_value(env: Mapping[str, str], name: str) -> str:
    if name in env:
        return str(env.get(name) or "").strip()
    return os.getenv(name, "").strip()


def _looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return not lowered or any(lowered.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def _check_auth(env: Mapping[str, str]) -> GoLiveCheck:
    api_key = _env_value(env, "BS_API_KEY") or configured_api_key()
    admin = _env_value(env, "BS_ADMIN_PASSWORD") or configured_admin_password()
    if not api_key and not admin:
        return GoLiveCheck(
            "runtime_authentication",
            "fail",
            "BS_API_KEY or BS_ADMIN_PASSWORD must be configured before shared use.",
            {"api_key_enabled": False, "password_login_enabled": False},
        )
    warnings = []
    if api_key and (len(api_key) < 24 or _looks_placeholder(api_key)):
        warnings.append("BS_API_KEY should be 24+ random characters and not a placeholder.")
    if admin and (len(admin) < 12 or _looks_placeholder(admin)):
        warnings.append("BS_ADMIN_PASSWORD should be 12+ random characters and not a placeholder.")
    return GoLiveCheck(
        "runtime_authentication",
        "warn" if warnings else "pass",
        "; ".join(warnings) if warnings else "Runtime authentication is configured.",
        {"api_key_enabled": bool(api_key), "password_login_enabled": bool(admin)},
    )


def _check_session_secret(env: Mapping[str, str]) -> GoLiveCheck:
    admin = _env_value(env, "BS_ADMIN_PASSWORD") or configured_admin_password()
    secret = _env_value(env, "BS_SESSION_SECRET")
    if not admin:
        return GoLiveCheck("session_secret", "pass", "Browser login is disabled, so session secret is not required.", {})
    if not secret or len(secret) < 32 or _looks_placeholder(secret):
        return GoLiveCheck(
            "session_secret",
            "fail",
            "BS_SESSION_SECRET must be a separate 32+ character random value when browser login is enabled.",
            {"configured": bool(secret), "length": len(secret)},
        )
    return GoLiveCheck("session_secret", "pass", "Session secret length looks safe for go-live.", {"length": len(secret)})


def _check_placeholders(env: Mapping[str, str]) -> GoLiveCheck:
    bad = []
    for key in SECRET_ENV_KEYS:
        value = _env_value(env, key)
        if value and _looks_placeholder(value):
            bad.append(key)
    return GoLiveCheck(
        "placeholder_secrets",
        "fail" if bad else "pass",
        "No placeholder runtime secrets detected." if not bad else f"Replace placeholder value(s): {', '.join(bad)}.",
        {"placeholder_keys": bad},
    )


def _check_docs_and_cookies(env: Mapping[str, str], deployment_mode: str) -> list[GoLiveCheck]:
    production = deployment_mode == "production"
    docs_disabled = _env_bool(env, "BS_DISABLE_DOCS", os.getenv("BS_DISABLE_DOCS", "0"))
    cookie_secure = _env_bool(env, "BS_COOKIE_SECURE", os.getenv("BS_COOKIE_SECURE", "0"))
    checks = []
    checks.append(
        GoLiveCheck(
            "api_docs_exposure",
            "pass" if docs_disabled else "fail" if production else "warn",
            "API docs are disabled." if docs_disabled else "Set BS_DISABLE_DOCS=1 before production exposure.",
            {"docs_disabled": docs_disabled, "deployment_mode": deployment_mode},
        )
    )
    checks.append(
        GoLiveCheck(
            "secure_cookie",
            "pass" if cookie_secure else "fail" if production else "warn",
            "Secure cookie flag is enabled." if cookie_secure else "Set BS_COOKIE_SECURE=1 when served over HTTPS.",
            {"cookie_secure": cookie_secure, "deployment_mode": deployment_mode},
        )
    )
    return checks


def _check_session_ttl() -> GoLiveCheck:
    try:
        ttl = session_ttl_seconds()
    except Exception as exc:  # pragma: no cover
        return GoLiveCheck("session_ttl", "fail", f"BS_SESSION_TTL_SECONDS could not be parsed: {exc}", {})
    ok = 300 <= ttl <= 24 * 60 * 60
    return GoLiveCheck(
        "session_ttl",
        "pass" if ok else "warn",
        f"Session TTL is {ttl} seconds." if ok else "Use a session TTL between 5 minutes and 24 hours.",
        {"seconds": ttl},
    )


def _check_data_paths() -> GoLiveCheck:
    paths = {
        "cases_root": _path_info(CaseHistoryService.default_root(), create_dir=True),
        "case_history": _path_info(CaseHistoryService.default_index_path(), create_dir=True, file_path=True),
        "audit_log": _path_info(audit_log_path(), create_dir=True, file_path=True),
        "backup_root": _path_info(BackupService.default_root(), create_dir=True),
    }
    failures = [name for name, info in paths.items() if not info.get("writable")]
    return GoLiveCheck(
        "persistent_data_paths",
        "fail" if failures else "pass",
        "Persistent data paths are writable." if not failures else f"Non-writable path(s): {', '.join(failures)}.",
        paths,
    )


def _check_audit() -> GoLiveCheck:
    enabled = audit_is_enabled()
    return GoLiveCheck(
        "audit_trail",
        "pass" if enabled else "warn",
        "Audit trail is enabled." if enabled else "Enable BS_AUDIT_ENABLED=1 for shared deployments.",
        {"enabled": enabled, "path": str(audit_log_path())},
    )


def _check_quality_and_repo(root: Path) -> list[GoLiveCheck]:
    checks: list[GoLiveCheck] = []
    try:
        quality = run_quality_gate(root)
        checks.append(
            GoLiveCheck(
                "quality_gate",
                "pass" if quality.get("status") == "pass" else "warn" if quality.get("status") == "warn" else "fail",
                f"Quality gate status is {quality.get('status')} with score {quality.get('score')}/100.",
                {"score": quality.get("score"), "summary": quality.get("summary")},
            )
        )
    except Exception as exc:  # pragma: no cover
        checks.append(GoLiveCheck("quality_gate", "fail", f"Quality gate failed to run: {exc}", {"error": str(exc)}))
    try:
        readiness = run_project_readiness(root)
        checks.append(
            GoLiveCheck(
                "project_readiness",
                "pass" if readiness.get("status") == "pass" else "warn" if readiness.get("status") == "warn" else "fail",
                f"Project readiness is {readiness.get('status')} with score {readiness.get('score')}/100.",
                {"score": readiness.get("score"), "summary": readiness.get("summary")},
            )
        )
    except Exception as exc:  # pragma: no cover
        checks.append(GoLiveCheck("project_readiness", "fail", f"Project readiness failed to run: {exc}", {"error": str(exc)}))
    return checks


def _score(checks: list[GoLiveCheck]) -> int:
    score = 100
    for check in checks:
        if check.status == "fail":
            score -= 20
        elif check.status == "warn":
            score -= 5
    return max(score, 0)


def _summary(checks: list[GoLiveCheck]) -> dict[str, int]:
    return {
        "passed": sum(1 for c in checks if c.status == "pass"),
        "warnings": sum(1 for c in checks if c.status == "warn"),
        "failed": sum(1 for c in checks if c.status == "fail"),
    }


def _next_steps(checks: list[GoLiveCheck]) -> list[str]:
    steps: list[str] = []
    failed_or_warn = [c for c in checks if c.status in {"fail", "warn"}]
    for check in failed_or_warn:
        if check.name == "runtime_authentication":
            steps.append("Run `python scripts/init_env.py --production --https --output .env` and set strong authentication secrets.")
        elif check.name == "session_secret":
            steps.append("Set BS_SESSION_SECRET to a unique 32+ character random value.")
        elif check.name == "placeholder_secrets":
            steps.append("Replace every `change-me-*` value before deployment.")
        elif check.name == "api_docs_exposure":
            steps.append("Set BS_DISABLE_DOCS=1 for shared or production deployments.")
        elif check.name == "secure_cookie":
            steps.append("Set BS_COOKIE_SECURE=1 when the console is served through HTTPS.")
        elif check.name == "audit_trail":
            steps.append("Keep BS_AUDIT_ENABLED=1 and back up the audit JSONL regularly.")
        elif check.name == "persistent_data_paths":
            steps.append("Fix write permissions for case, audit, and backup paths before go-live.")
    if not steps:
        steps.append("Run `make ci-local` and create one test backup before publishing the service URL.")
    return steps


def run_go_live_check(root: str | Path = ".", *, env: Mapping[str, str] | None = None, deployment_mode: str | None = None) -> dict[str, Any]:
    """Return final deployment/go-live readiness results."""
    root_path = Path(root).resolve()
    env_map: Mapping[str, str] = env or os.environ
    mode = (deployment_mode or _env_value(env_map, "BS_DEPLOYMENT_MODE") or "local").strip().lower()
    checks: list[GoLiveCheck] = [
        _check_auth(env_map),
        _check_session_secret(env_map),
        _check_placeholders(env_map),
        _check_session_ttl(),
        _check_data_paths(),
        _check_audit(),
    ]
    checks.extend(_check_docs_and_cookies(env_map, mode))
    checks.extend(_check_quality_and_repo(root_path))

    summary = _summary(checks)
    score = _score(checks)
    status = "fail" if summary["failed"] else "warn" if summary["warnings"] else "pass"
    return {
        "success": status != "fail",
        "status": status,
        "score": score,
        "deployment_mode": mode,
        "summary": summary,
        "checks": [c.as_dict() for c in checks],
        "next_steps": _next_steps(checks),
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# BreachScope Go-Live Readiness Report",
        "",
        f"- Status: **{result.get('status')}**",
        f"- Score: **{result.get('score')}/100**",
        f"- Deployment mode: `{result.get('deployment_mode')}`",
        "",
        "## Checks",
        "",
        "| Status | Check | Message |",
        "|---|---|---|",
    ]
    for check in result.get("checks", []):
        lines.append(f"| {str(check.get('status', '')).upper()} | `{check.get('name', '')}` | {str(check.get('message', '')).replace('|', '\\|')} |")
    lines.extend(["", "## Next steps", ""])
    for step in result.get("next_steps", []):
        lines.append(f"- {step}")
    return "\n".join(lines) + "\n"
