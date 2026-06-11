"""Operational health, metrics, and self-test helpers for BreachScope."""
from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api.services.audit_log import AuditLogService, audit_is_enabled, audit_log_path
from api.services.backup_service import BackupService
from api.services.case_history import CaseHistoryService
from api.security import auth_is_enabled, configured_admin_password, configured_api_key, session_ttl_seconds
from breachscope.demo_scenarios import SCENARIOS, write_demo_scenario
from breachscope.pipeline import Pipeline
from breachscope.rulepack import summarize_rules
from breachscope.rules import load_rules

SERVICE_STARTED_AT = time.time()
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class Check:
    name: str
    status: str
    message: str
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        data = {"name": self.name, "status": self.status, "message": self.message}
        if self.details:
            data["details"] = self.details
        return data


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _bool_env(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _path_info(path: Path, *, create_dir: bool = False, file_path: bool = False) -> dict[str, Any]:
    expanded = path.expanduser()
    target_dir = expanded.parent if file_path else expanded
    result: dict[str, Any] = {
        "path": str(expanded),
        "exists": expanded.exists(),
        "directory": str(target_dir),
        "directory_exists": target_dir.exists(),
        "writable": False,
        "free_bytes": None,
        "error": None,
    }
    try:
        if create_dir:
            target_dir.mkdir(parents=True, exist_ok=True)
        if target_dir.exists():
            probe = target_dir / f".bs_probe_{os.getpid()}_{int(time.time() * 1000)}"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            result["writable"] = True
            usage = shutil.disk_usage(target_dir)
            result["free_bytes"] = usage.free
    except Exception as exc:  # pragma: no cover - exact OS errors vary
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _safe_count_file_lines(path: Path, limit: int = 100_000) -> int:
    if not path.exists() or not path.is_file():
        return 0
    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fp:
            for count, _ in enumerate(fp, 1):
                if count >= limit:
                    break
    except OSError:
        return 0
    return count


def _current_rule_summary() -> dict[str, Any]:
    rules = load_rules(PROJECT_ROOT / "rules")
    summary = summarize_rules(rules)
    return {
        "total_rules": len(rules),
        "unique_techniques": summary.get("unique_techniques", 0),
        "coverage_percent_core_windows": summary.get("coverage_percent_core_windows", 0),
        "tactic_counts": summary.get("tactic_counts", {}),
    }


def live_status() -> dict[str, Any]:
    return {
        "status": "live",
        "service": "BreachScope",
        "version": "1.0.0",
        "started_at_epoch": SERVICE_STARTED_AT,
        "uptime_seconds": round(time.time() - SERVICE_STARTED_AT, 3),
        "timestamp": _now_iso(),
        "process": {"pid": os.getpid(), "python": sys.version.split()[0], "platform": platform.platform()},
    }


def readiness_status() -> dict[str, Any]:
    checks = []
    checks.append(_check_path("cases_root", CaseHistoryService.default_root(), create_dir=True))
    checks.append(_check_path("case_history", CaseHistoryService.default_index_path(), create_dir=True, file_path=True))
    checks.append(_check_path("audit_log", audit_log_path(), create_dir=True, file_path=True))
    checks.append(_check_path("backup_root", BackupService.default_root(), create_dir=True))
    checks.append(_check_rulepack())
    checks.append(_check_templates())
    checks.append(_check_scenarios())
    failures = [c for c in checks if c.status == "fail"]
    warnings = [c for c in checks if c.status == "warn"]
    return {
        "status": "ready" if not failures else "not_ready",
        "summary": {"pass": len([c for c in checks if c.status == "pass"]), "warn": len(warnings), "fail": len(failures)},
        "checks": [c.as_dict() for c in checks],
        "timestamp": _now_iso(),
    }


def _check_path(name: str, path: Path, *, create_dir: bool = False, file_path: bool = False) -> Check:
    info = _path_info(path, create_dir=create_dir, file_path=file_path)
    if info["writable"]:
        return Check(name, "pass", "path is writable", info)
    return Check(name, "fail", "path is not writable", info)


def _check_rulepack() -> Check:
    try:
        summary = _current_rule_summary()
        total = int(summary.get("total_rules") or 0)
        status = "pass" if total >= 50 else "warn" if total > 0 else "fail"
        return Check("rulepack", status, f"{total} rules loaded", summary)
    except Exception as exc:
        return Check("rulepack", "fail", f"rulepack load failed: {exc}")


def _check_templates() -> Check:
    required = [PROJECT_ROOT / "templates" / "web_index.html", PROJECT_ROOT / "templates" / "report.html.j2"]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        return Check("templates", "fail", "required templates are missing", {"missing": missing})
    return Check("templates", "pass", "required templates exist", {"count": len(required)})


def _check_scenarios() -> Check:
    count = len(SCENARIOS)
    status = "pass" if count >= 10 else "warn"
    return Check("demo_scenarios", status, f"{count} built-in scenarios available", {"count": count})


def metrics_snapshot() -> dict[str, Any]:
    cases = CaseHistoryService().list_cases(limit=1000)
    backups = BackupService().list_backups(limit=1000)
    audit_path = audit_log_path()
    audit_events = _safe_count_file_lines(audit_path)
    risk_counts: dict[str, int] = {}
    finding_total = 0
    for case in cases:
        risk = str(case.get("risk_level") or "none")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        try:
            finding_total += int(case.get("finding_count") or 0)
        except (TypeError, ValueError):
            pass
    return {
        "timestamp": _now_iso(),
        "uptime_seconds": round(time.time() - SERVICE_STARTED_AT, 3),
        "cases_total": len(cases),
        "findings_total_indexed": finding_total,
        "case_risk_levels": risk_counts,
        "backups_total": len(backups),
        "audit_events_total": audit_events,
        "audit_enabled": audit_is_enabled(),
        "auth_enabled": auth_is_enabled(),
        "rulepack": _current_rule_summary(),
        "paths": {
            "cases_root": str(CaseHistoryService.default_root()),
            "case_history": str(CaseHistoryService.default_index_path()),
            "audit_log": str(audit_path),
            "backup_root": str(BackupService.default_root()),
        },
    }


def prometheus_metrics(snapshot: dict[str, Any] | None = None) -> str:
    s = snapshot or metrics_snapshot()
    lines = [
        "# HELP breachscope_uptime_seconds Process uptime in seconds.",
        "# TYPE breachscope_uptime_seconds gauge",
        f"breachscope_uptime_seconds {float(s.get('uptime_seconds') or 0)}",
        "# HELP breachscope_cases_total Number of indexed analysis cases.",
        "# TYPE breachscope_cases_total gauge",
        f"breachscope_cases_total {int(s.get('cases_total') or 0)}",
        "# HELP breachscope_findings_total_indexed Total findings recorded in case index.",
        "# TYPE breachscope_findings_total_indexed gauge",
        f"breachscope_findings_total_indexed {int(s.get('findings_total_indexed') or 0)}",
        "# HELP breachscope_backups_total Number of local backup archives.",
        "# TYPE breachscope_backups_total gauge",
        f"breachscope_backups_total {int(s.get('backups_total') or 0)}",
        "# HELP breachscope_audit_events_total Number of audit log records.",
        "# TYPE breachscope_audit_events_total gauge",
        f"breachscope_audit_events_total {int(s.get('audit_events_total') or 0)}",
        "# HELP breachscope_rulepack_rules_total Number of loaded detection rules.",
        "# TYPE breachscope_rulepack_rules_total gauge",
        f"breachscope_rulepack_rules_total {int((s.get('rulepack') or {}).get('total_rules') or 0)}",
        "# HELP breachscope_rulepack_unique_techniques Number of unique MITRE techniques in the rulepack.",
        "# TYPE breachscope_rulepack_unique_techniques gauge",
        f"breachscope_rulepack_unique_techniques {int((s.get('rulepack') or {}).get('unique_techniques') or 0)}",
    ]
    for level, count in sorted((s.get("case_risk_levels") or {}).items()):
        safe = str(level).replace('"', "")
        lines.append(f'breachscope_cases_by_risk_level{{level="{safe}"}} {int(count)}')
    return "\n".join(lines) + "\n"


def config_diagnostics() -> dict[str, Any]:
    checks: list[Check] = []
    checks.extend(_security_checks())
    # Re-run readiness checks as Check objects so callers get consistent severity details.
    checks.append(_check_path("cases_root", CaseHistoryService.default_root(), create_dir=True))
    checks.append(_check_path("case_history", CaseHistoryService.default_index_path(), create_dir=True, file_path=True))
    checks.append(_check_path("audit_log", audit_log_path(), create_dir=True, file_path=True))
    checks.append(_check_path("backup_root", BackupService.default_root(), create_dir=True))
    checks.append(_check_rulepack())
    checks.append(_check_templates())
    checks.append(_check_scenarios())
    failures = [c for c in checks if c.status == "fail"]
    warnings = [c for c in checks if c.status == "warn"]
    return {
        "status": "fail" if failures else "warn" if warnings else "pass",
        "summary": {"pass": len([c for c in checks if c.status == "pass"]), "warn": len(warnings), "fail": len(failures)},
        "checks": [c.as_dict() for c in checks],
        "timestamp": _now_iso(),
    }


def _security_checks() -> list[Check]:
    checks: list[Check] = []
    api_key = configured_api_key()
    admin_password = configured_admin_password()
    session_secret = os.getenv("BS_SESSION_SECRET", "").strip()
    if not (api_key or admin_password):
        checks.append(Check("auth_enabled", "warn", "authentication is disabled; acceptable only for local demos"))
    else:
        checks.append(Check("auth_enabled", "pass", "authentication is enabled"))
    if api_key and (len(api_key) < 24 or api_key.startswith("change-me")):
        checks.append(Check("api_key_strength", "warn", "BS_API_KEY should be a long random value"))
    elif api_key:
        checks.append(Check("api_key_strength", "pass", "BS_API_KEY length looks acceptable"))
    if admin_password and (len(admin_password) < 12 or admin_password.startswith("change-me")):
        checks.append(Check("admin_password_strength", "warn", "BS_ADMIN_PASSWORD should be changed to a long random password"))
    elif admin_password:
        checks.append(Check("admin_password_strength", "pass", "admin password length looks acceptable"))
    if admin_password:
        if not session_secret or session_secret.startswith("change-me") or len(session_secret) < 32:
            checks.append(Check("session_secret", "warn", "BS_SESSION_SECRET should be a separate 32+ character random value"))
        elif session_secret in {api_key, admin_password}:
            checks.append(Check("session_secret", "warn", "BS_SESSION_SECRET should not equal the API key or admin password"))
        else:
            checks.append(Check("session_secret", "pass", "session secret looks acceptable"))
    if _bool_env("BS_COOKIE_SECURE", "0"):
        checks.append(Check("cookie_secure", "pass", "Secure cookie flag is enabled"))
    elif admin_password:
        checks.append(Check("cookie_secure", "warn", "set BS_COOKIE_SECURE=1 when serving behind HTTPS"))
    if _bool_env("BS_DISABLE_DOCS", "0"):
        checks.append(Check("api_docs", "pass", "API docs are disabled"))
    else:
        checks.append(Check("api_docs", "warn", "consider BS_DISABLE_DOCS=1 for shared deployments"))
    try:
        ttl = session_ttl_seconds()
        status = "pass" if 300 <= ttl <= 24 * 60 * 60 else "warn"
        checks.append(Check("session_ttl", status, f"session TTL is {ttl} seconds", {"seconds": ttl}))
    except Exception as exc:
        checks.append(Check("session_ttl", "fail", f"session TTL could not be parsed: {exc}"))
    return checks


def run_self_test(*, render_pdf: bool = False) -> dict[str, Any]:
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="bs_selftest_") as tmp:
        tmp_path = Path(tmp)
        input_dir = tmp_path / "input"
        out_prefix = tmp_path / "out" / "report"
        write_demo_scenario("powershell_downloader", input_dir)
        pipeline = Pipeline(rules_dir=PROJECT_ROOT / "rules", min_severity="low", max_events=1000)
        html_path, finding_count = pipeline.run(input_dir=input_dir, out_prefix=out_prefix, export_json=True, export_csv=True, render_pdf=render_pdf)
        artifacts = {
            "html": html_path.exists(),
            "json": out_prefix.with_suffix(".json").exists(),
            "csv": out_prefix.with_suffix(".csv").exists(),
            "iocs": out_prefix.with_suffix(".iocs.csv").exists(),
            "rules": out_prefix.with_suffix(".rules.csv").exists(),
            "manifest": out_prefix.with_suffix(".manifest.json").exists(),
            "zip": out_prefix.with_suffix(".zip").exists(),
            "pdf": out_prefix.with_suffix(".pdf").exists(),
        }
        report_data = json.loads(out_prefix.with_suffix(".json").read_text(encoding="utf-8"))
        risk = (report_data.get("summary") or {}).get("risk") or {}
        passed = finding_count > 0 and all(artifacts[k] for k in ("html", "json", "csv", "iocs", "rules", "manifest", "zip"))
        return {
            "success": bool(passed),
            "scenario": "powershell_downloader",
            "events": 4,
            "findings": finding_count,
            "risk_score": risk.get("score", 0),
            "risk_level": risk.get("level", "none"),
            "artifacts": artifacts,
            "elapsed_seconds": round(time.time() - started, 3),
            "timestamp": _now_iso(),
        }
