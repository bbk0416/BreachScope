"""Pre-publication quality and security gate for BreachScope.

The readiness checker answers "does the repository look complete?". This
quality gate answers the next release-manager question: "does this checkout
contain obvious operational risks, leaked secrets, broken documentation links,
or files that should never ship?"
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from breachscope.release import DEFAULT_EXCLUDES, iter_release_files, should_exclude


@dataclass(frozen=True)
class QualityIssue:
    severity: str
    path: str
    message: str
    line: int | None = None
    evidence: str | None = None


@dataclass(frozen=True)
class QualityCheck:
    name: str
    status: str
    message: str
    details: dict[str, Any]


MAX_TEXT_FILE_BYTES = 512 * 1024
MAX_RECOMMENDED_FILE_BYTES = 2 * 1024 * 1024
MAX_RELEASE_FILE_COUNT = 1000

EXCLUDED_SCAN_DIRS = {
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
}

EXCLUDED_SCAN_GLOBS = (
    "out/*",
    "out_*/*",
    "*.zip",
    "*.pdf",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.pyc",
    "*.pyo",
    "*.evtx",
)

FORBIDDEN_RUNTIME_PATTERNS = (
    ".env",
    ".env.local",
    ".env.production",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.log",
    "*.jsonl",
    "case_history.json",
    "auth_rate_limit.json",
    "audit.jsonl",
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    (
        "dotenv_secret_assignment",
        re.compile(
            r"\b(?:BS_API_KEY|BS_ADMIN_PASSWORD|BS_SESSION_SECRET|BS_AUDIT_CHAIN_SECRET|API_KEY|SECRET|TOKEN|PASSWORD)\b\s*=\s*[\"']?([A-Za-z0-9_./+=:@!#$%^&*~-]{24,})"
        ),
    ),
)

PLACEHOLDER_WORDS = {
    "change-me",
    "changeme",
    "example",
    "placeholder",
    "your_",
    "your-",
    "redacted",
    "dummy",
    "sample",
    "test",
    "local-demo",
    "please-change",
    "ci-password",
    "ci-session",
    "긴_랜덤",
    "관리자_비밀번호",
}

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _as_posix(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_excluded(path: Path, root: Path) -> bool:
    rel = _as_posix(path, root)
    parts = rel.split("/")
    if any(part in EXCLUDED_SCAN_DIRS for part in parts):
        return True
    return any(fnmatch.fnmatch(rel, pattern) for pattern in EXCLUDED_SCAN_GLOBS)


def _iter_candidate_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _is_excluded(path, root):
            continue
        files.append(path)
    return sorted(files, key=lambda p: _as_posix(p, root))


def _is_probably_text(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    return True


def _redact_evidence(value: str, keep: int = 4) -> str:
    stripped = value.strip()
    if len(stripped) <= keep * 2:
        return "<redacted>"
    return f"{stripped[:keep]}…{stripped[-keep:]}"


def _looks_like_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(word.lower() in lowered for word in PLACEHOLDER_WORDS)


def _status_from_issues(issues: list[QualityIssue]) -> str:
    severities = {issue.severity for issue in issues}
    if "fail" in severities:
        return "fail"
    if "warn" in severities:
        return "warn"
    return "pass"


def _issue_payload(issues: list[QualityIssue], *, limit: int = 50) -> list[dict[str, Any]]:
    return [asdict(issue) for issue in issues[:limit]]


def _forbidden_runtime_file_check(root: Path, files: list[Path]) -> QualityCheck:
    issues: list[QualityIssue] = []
    for path in files:
        rel = _as_posix(path, root)
        basename = path.name
        if rel.startswith("samples/scenarios/") and basename.endswith(".jsonl"):
            continue
        if any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(basename, pattern) for pattern in FORBIDDEN_RUNTIME_PATTERNS):
            # .env.example is intentionally committed; only exact runtime .env variants fail.
            if basename == ".env.example":
                continue
            issues.append(QualityIssue("fail", rel, "Runtime, secret, or local state file should not be committed."))
    return QualityCheck(
        name="forbidden_runtime_files",
        status=_status_from_issues(issues),
        message="No forbidden runtime/local-state files found." if not issues else f"Found {len(issues)} forbidden runtime file(s).",
        details={"issues": _issue_payload(issues), "patterns": list(FORBIDDEN_RUNTIME_PATTERNS)},
    )


def _secret_scan_check(root: Path, files: list[Path]) -> QualityCheck:
    issues: list[QualityIssue] = []
    for path in files:
        rel = _as_posix(path, root)
        try:
            if path.stat().st_size > MAX_TEXT_FILE_BYTES or not _is_probably_text(path):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if _looks_like_placeholder(line):
                continue
            for label, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                evidence = match.group(1) if match.groups() else match.group(0)
                issues.append(
                    QualityIssue(
                        "fail",
                        rel,
                        f"Potential secret detected: {label}.",
                        line=lineno,
                        evidence=_redact_evidence(evidence),
                    )
                )
    return QualityCheck(
        name="secret_scan",
        status=_status_from_issues(issues),
        message="No high-confidence secret patterns found." if not issues else f"Found {len(issues)} potential secret(s).",
        details={"issues": _issue_payload(issues), "scanned_files": len(files)},
    )


def _large_file_check(root: Path, files: list[Path]) -> QualityCheck:
    issues: list[QualityIssue] = []
    for path in files:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_RECOMMENDED_FILE_BYTES:
            issues.append(
                QualityIssue(
                    "warn",
                    _as_posix(path, root),
                    f"Large file is committed ({size} bytes). Confirm it belongs in source control.",
                )
            )
    return QualityCheck(
        name="large_files",
        status=_status_from_issues(issues),
        message="No unexpectedly large source files found." if not issues else f"Found {len(issues)} large file(s).",
        details={"issues": _issue_payload(issues), "threshold_bytes": MAX_RECOMMENDED_FILE_BYTES},
    )


def _markdown_link_check(root: Path, files: list[Path]) -> QualityCheck:
    issues: list[QualityIssue] = []
    markdown_files = [path for path in files if path.suffix.lower() == ".md"]
    for path in markdown_files:
        rel = _as_posix(path, root)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in MARKDOWN_LINK_RE.finditer(line):
                raw_target = match.group(1).strip()
                if not raw_target or raw_target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                if raw_target.startswith("sandbox:") or raw_target.startswith("javascript:"):
                    issues.append(QualityIssue("fail", rel, f"Unsupported or unsafe Markdown link target: {raw_target}", line=lineno))
                    continue
                target = raw_target.split("#", 1)[0].strip()
                if not target:
                    continue
                if target.startswith("/"):
                    candidate = root / target.lstrip("/")
                else:
                    candidate = (path.parent / target).resolve()
                try:
                    candidate.relative_to(root)
                except ValueError:
                    issues.append(QualityIssue("warn", rel, f"Markdown link points outside repository: {raw_target}", line=lineno))
                    continue
                if not candidate.exists():
                    issues.append(QualityIssue("warn", rel, f"Broken internal Markdown link: {raw_target}", line=lineno))
    return QualityCheck(
        name="markdown_links",
        status=_status_from_issues(issues),
        message="Internal Markdown links resolve." if not issues else f"Found {len(issues)} Markdown link issue(s).",
        details={"issues": _issue_payload(issues), "markdown_files": len(markdown_files)},
    )


def _release_exclusion_check(root: Path) -> QualityCheck:
    release_files = iter_release_files(root)
    issues: list[QualityIssue] = []
    for path in release_files:
        rel = _as_posix(path, root)
        basename = path.name
        if any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(basename, pattern) for pattern in FORBIDDEN_RUNTIME_PATTERNS):
            if basename == ".env.example":
                continue
            issues.append(QualityIssue("fail", rel, "Forbidden runtime file would be included in source release."))
        if should_exclude(rel, DEFAULT_EXCLUDES):
            issues.append(QualityIssue("fail", rel, "Release iterator included a file that should be excluded."))
    if len(release_files) > MAX_RELEASE_FILE_COUNT:
        issues.append(QualityIssue("warn", ".", f"Release package has {len(release_files)} files; review package size."))
    return QualityCheck(
        name="release_hygiene",
        status=_status_from_issues(issues),
        message="Release file list excludes runtime state and generated artifacts." if not issues else f"Found {len(issues)} release hygiene issue(s).",
        details={
            "issues": _issue_payload(issues),
            "release_file_count": len(release_files),
            "exclude_patterns": list(DEFAULT_EXCLUDES),
        },
    )


def _required_security_docs_check(root: Path) -> QualityCheck:
    expected = {
        "SECURITY.md": ["report", "vulnerability"],
        "docs/DEPLOYMENT.md": ["BS_API_KEY", "BS_ADMIN_PASSWORD", "BS_SESSION_SECRET"],
        "docs/CI_CD.md": ["GitHub Actions", "pytest"],
        "docs/RELEASE.md": ["SHA256", "release_manifest"],
    }
    issues: list[QualityIssue] = []
    for rel, needles in expected.items():
        path = root / rel
        if not path.exists():
            issues.append(QualityIssue("fail", rel, "Required security/release document is missing."))
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        missing = [needle for needle in needles if needle.lower() not in lowered]
        if missing:
            issues.append(QualityIssue("warn", rel, f"Document is missing expected term(s): {', '.join(missing)}"))
    return QualityCheck(
        name="security_release_docs",
        status=_status_from_issues(issues),
        message="Security, deployment, CI/CD, and release docs contain expected guidance." if not issues else f"Found {len(issues)} documentation gap(s).",
        details={"issues": _issue_payload(issues), "documents": list(expected.keys())},
    )


def run_quality_gate(root: str | Path = ".") -> dict[str, Any]:
    """Run repository quality/security checks and return a structured result."""
    root_path = Path(root).resolve()
    files = _iter_candidate_files(root_path)
    checks = [
        _forbidden_runtime_file_check(root_path, files),
        _secret_scan_check(root_path, files),
        _large_file_check(root_path, files),
        _markdown_link_check(root_path, files),
        _release_exclusion_check(root_path),
        _required_security_docs_check(root_path),
    ]
    pass_count = sum(1 for check in checks if check.status == "pass")
    warn_count = sum(1 for check in checks if check.status == "warn")
    fail_count = sum(1 for check in checks if check.status == "fail")
    score = max(0, min(100, round(100 * (pass_count + 0.5 * warn_count) / max(1, len(checks)) - fail_count * 12)))
    status = "fail" if fail_count else "warn" if warn_count else "pass"
    return {
        "success": fail_count == 0,
        "status": status,
        "score": score,
        "summary": {"checks": len(checks), "passed": pass_count, "warnings": warn_count, "failed": fail_count},
        "root": str(root_path),
        "scanned_files": len(files),
        "checks": [asdict(check) for check in checks],
    }


def render_markdown(result: dict[str, Any]) -> str:
    """Render quality gate results as Markdown."""
    lines = [
        "# BreachScope Quality Gate Report",
        "",
        f"- Status: **{result['status']}**",
        f"- Score: **{result['score']}/100**",
        f"- Root: `{result['root']}`",
        f"- Scanned files: **{result.get('scanned_files', 0)}**",
        "",
        "| Check | Status | Message |",
        "|---|---:|---|",
    ]
    for check in result.get("checks", []):
        lines.append(f"| `{check['name']}` | {check['status']} | {check['message']} |")
    lines.append("")
    return "\n".join(lines)


def write_json(result: dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
