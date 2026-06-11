"""Final public-launch packaging helpers for BreachScope.

The release bundle answers "what can be installed?". The demo pack answers
"what should a reviewer open?". The showcase answers "what can I host on
GitHub Pages?". This module ties those together into one publish-prep bundle
and verifies that generated ZIP artifacts do not contain local runtime debris.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from breachscope.demo_pack import build_demo_pack
from breachscope.golive import run_go_live_check
from breachscope.project_readiness import run_project_readiness
from breachscope.quality_gate import run_quality_gate
from breachscope.release import build_release_bundle, get_project_metadata, sha256_file
from breachscope.showcase import build_showcase


@dataclass(frozen=True)
class PublishArtifact:
    path: str
    size_bytes: int
    sha256: str
    purpose: str


FORBIDDEN_ZIP_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git"}
FORBIDDEN_ZIP_SUFFIXES = (".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".log")
FORBIDDEN_ZIP_NAMES = {".env", ".env.local", ".env.production", "audit.jsonl", "case_history.json", "auth_rate_limit.json"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_text(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.rstrip() + "\n", encoding="utf-8")


def _artifact(path: Path, root: Path, purpose: str) -> PublishArtifact:
    return PublishArtifact(
        path=path.relative_to(root).as_posix(),
        size_bytes=path.stat().st_size,
        sha256=sha256_file(path),
        purpose=purpose,
    )


def _production_env(out: Path) -> dict[str, str]:
    """Return a non-persistent strong env profile for go-live validation."""
    return {
        "BS_API_KEY": secrets.token_urlsafe(32),
        "BS_ADMIN_PASSWORD": secrets.token_urlsafe(24),
        "BS_SESSION_SECRET": secrets.token_urlsafe(48),
        "BS_AUDIT_CHAIN_SECRET": secrets.token_urlsafe(32),
        "BS_DEPLOYMENT_MODE": "production",
        "BS_DISABLE_DOCS": "1",
        "BS_COOKIE_SECURE": "1",
        "BS_AUDIT_ENABLED": "1",
        "BS_CASES_ROOT": str(out / "runtime_check" / "cases"),
        "BS_CASE_HISTORY_PATH": str(out / "runtime_check" / "case_history.json"),
        "BS_AUDIT_LOG_PATH": str(out / "runtime_check" / "audit.jsonl"),
        "BS_BACKUP_ROOT": str(out / "runtime_check" / "backups"),
        "BS_AUTH_RATE_LIMIT_PATH": str(out / "runtime_check" / "auth_rate_limit.json"),
    }


def inspect_zip_hygiene(zip_path: str | Path) -> dict[str, Any]:
    """Inspect a ZIP for files that should not be shipped publicly."""
    path = Path(zip_path)
    issues: list[dict[str, str]] = []
    with ZipFile(path, "r") as zf:
        names = [name for name in zf.namelist() if name and not name.endswith("/")]
    for name in names:
        parts = set(Path(name).parts)
        basename = Path(name).name
        suffix = Path(name).suffix.lower()
        if parts & FORBIDDEN_ZIP_PARTS:
            issues.append({"path": name, "reason": "generated/cache directory is included"})
        elif basename in FORBIDDEN_ZIP_NAMES:
            issues.append({"path": name, "reason": "runtime/local secret file is included"})
        elif suffix in FORBIDDEN_ZIP_SUFFIXES:
            issues.append({"path": name, "reason": "generated/runtime file extension is included"})
    return {
        "path": str(path),
        "file_count": len(names),
        "status": "pass" if not issues else "fail",
        "issues": issues,
    }


def _render_launch_summary(payload: dict[str, Any]) -> str:
    artifacts = payload.get("artifacts", [])
    lines = [
        "# BreachScope Public Launch Summary",
        "",
        f"- Generated at: `{payload.get('generated_at')}`",
        f"- Version: **{payload.get('metadata', {}).get('version', 'unknown')}**",
        f"- Project readiness: **{payload.get('project_readiness', {}).get('score')}/100 ({payload.get('project_readiness', {}).get('status')})**",
        f"- Quality gate: **{payload.get('quality_gate', {}).get('score')}/100 ({payload.get('quality_gate', {}).get('status')})**",
        f"- Go-Live readiness profile: **{payload.get('go_live', {}).get('score')}/100 ({payload.get('go_live', {}).get('status')})**",
        "",
        "## Open first",
        "",
        "1. `showcase/index.html` — GitHub Pages용 정적 랜딩 페이지",
        "2. `demo_pack/breachscope-demo-pack.zip` — 면접/외부 공유용 데모 핸드오프 ZIP",
        "3. `dist/SHA256SUMS.txt` — 릴리즈 산출물 checksum",
        "4. `GITHUB_PUBLISH_COMMANDS.md` — 업로드/태그/Pages 설정 순서",
        "",
        "## Artifacts",
        "",
        "| Path | Purpose | SHA-256 |",
        "|---|---|---|",
    ]
    for item in artifacts:
        lines.append(f"| `{item['path']}` | {item['purpose']} | `{item['sha256']}` |")
    lines.extend([
        "",
        "## ZIP hygiene",
        "",
        "| ZIP | Status | Files | Issues |",
        "|---|---:|---:|---:|",
    ])
    for check in payload.get("zip_hygiene", []):
        lines.append(
            f"| `{Path(check['path']).name}` | {check['status']} | {check.get('file_count', 0)} | {len(check.get('issues', []))} |"
        )
    return "\n".join(lines)


def _render_publish_commands() -> str:
    return "\n".join([
        "# GitHub Publish Commands",
        "",
        "## 1. Final local checks",
        "",
        "```bash",
        "make ci-local",
        "python scripts/publish_prep.py --clean",
        "```",
        "",
        "## 2. Push source",
        "",
        "```bash",
        "git status",
        "git add .",
        "git commit -m \"Prepare BreachScope public release\"",
        "git branch -M main",
        "git remote add origin https://github.com/bbk0416/BreachScope.git  # 이미 있으면 생략",
        "git push -u origin main",
        "```",
        "",
        "## 3. Create the first release tag",
        "",
        "```bash",
        "git tag v1.0.0",
        "git push origin v1.0.0",
        "```",
        "",
        "## 4. Enable GitHub Pages",
        "",
        "- Repository Settings → Pages",
        "- Source: GitHub Actions 또는 `/docs`/`gh-pages` 전략 중 선택",
        "- 정적 결과물은 `out/publish/showcase/index.html` 기준으로 확인",
        "",
        "## 5. Do not commit",
        "",
        "- `.env`",
        "- `out/`, `dist/`, `*.jsonl`, `*.db`, `*.log`",
        "- 실제 고객/기관 로그",
        "- API Key, 관리자 비밀번호, 세션 시크릿",
    ])


def _render_release_note(payload: dict[str, Any]) -> str:
    metadata = payload.get("metadata", {})
    return "\n".join([
        f"# BreachScope {metadata.get('version', '1.0.0')} Public Release Note",
        "",
        "## Summary",
        "",
        "BreachScope is a product-style DFIR portfolio console for Windows-centric security-log analysis. It combines ATT&CK-aligned detections, IOC extraction, incident timeline reconstruction, case workflow management, Korean PDF reporting, audit logs, backups, health checks, metrics, CI/CD, release checksums, quality gates, go-live checks, demo packs, and a static showcase.",
        "",
        "## Recommended assets to attach",
        "",
        "- `dist/breachscope-1.0.0-source.zip`",
        "- `dist/SHA256SUMS.txt`",
        "- `dist/release_manifest.json`",
        "- `demo_pack/breachscope-demo-pack.zip`",
        "- `showcase/breachscope-showcase.zip`",
        "",
        "## Safe positioning",
        "",
        "Use: product-style DFIR portfolio console / internal DFIR prototype / detection-reporting case-management demo.",
        "",
        "Avoid: EDR replacement / MITRE-certified coverage / production-ready commercial forensic suite.",
    ])


def _write_checksums(out: Path, artifacts: list[PublishArtifact]) -> None:
    lines = [f"{artifact.sha256}  {artifact.path}" for artifact in sorted(artifacts, key=lambda item: item.path)]
    _write_text(out / "SHA256SUMS.txt", "\n".join(lines))


def _zip_publish_pack(out: Path) -> Path:
    zip_path = out / "breachscope-public-launch-pack.zip"
    if zip_path.exists():
        zip_path.unlink()
    with ZipFile(zip_path, "w", ZIP_DEFLATED) as zf:
        for path in sorted(out.rglob("*")):
            if not path.is_file() or path == zip_path:
                continue
            rel = path.relative_to(out).as_posix()
            # runtime_check only exists to validate write paths; it is not a launch artifact.
            if rel.startswith("runtime_check/"):
                continue
            zf.write(path, f"breachscope-public-launch-pack/{rel}")
    return zip_path


def build_publish_prep(
    repo_root: str | Path = ".",
    output_dir: str | Path | None = None,
    *,
    clean: bool = False,
    render_pdf: bool = True,
) -> dict[str, Any]:
    """Build a final publish-prep package and return a structured manifest."""
    root = Path(repo_root).resolve()
    out = Path(output_dir).resolve() if output_dir else root / "out" / "publish"
    if clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    release = build_release_bundle(root, out / "dist")
    demo_pack = build_demo_pack(root, out / "demo_pack", clean=True, render_pdf=render_pdf)
    showcase = build_showcase(root, out / "showcase", clean=True, render_pdf=render_pdf)
    readiness = run_project_readiness(root)
    quality = run_quality_gate(root)
    go_live = run_go_live_check(root, env=_production_env(out), deployment_mode="production")
    metadata = asdict(get_project_metadata(root))

    artifact_paths: list[tuple[Path, str]] = []
    for artifact in release.get("artifacts", []):
        artifact_paths.append((Path(artifact["path"]), "Release artifact"))
    artifact_paths.extend([
        (Path(demo_pack["zip_path"]), "Shareable demo handoff ZIP"),
        (Path(showcase["zip_path"]), "GitHub Pages static showcase ZIP"),
    ])

    artifacts: list[PublishArtifact] = []
    for path, purpose in artifact_paths:
        if path.exists():
            artifacts.append(_artifact(path, out, purpose))

    zip_hygiene = [inspect_zip_hygiene(path) for path, _ in artifact_paths if path.exists() and path.suffix.lower() == ".zip"]
    zip_hygiene_status = "pass" if all(item["status"] == "pass" for item in zip_hygiene) else "fail"

    payload: dict[str, Any] = {
        "success": readiness.get("status") == "pass"
        and quality.get("status") == "pass"
        and go_live.get("status") == "pass"
        and zip_hygiene_status == "pass",
        "generated_at": _utc_now_iso(),
        "output_dir": str(out),
        "metadata": metadata,
        "project_readiness": {"status": readiness.get("status"), "score": readiness.get("score"), "summary": readiness.get("summary")},
        "quality_gate": {"status": quality.get("status"), "score": quality.get("score"), "summary": quality.get("summary")},
        "go_live": {"status": go_live.get("status"), "score": go_live.get("score"), "summary": go_live.get("summary")},
        "release": release,
        "demo_pack": {"zip_path": demo_pack.get("zip_path"), "zip_sha256": demo_pack.get("zip_sha256"), "demo_summary": demo_pack.get("demo_summary")},
        "showcase": {"zip_path": showcase.get("zip_path"), "zip_sha256": showcase.get("zip_sha256"), "demo_summary": showcase.get("demo_summary")},
        "zip_hygiene_status": zip_hygiene_status,
        "zip_hygiene": zip_hygiene,
        "artifacts": [asdict(item) for item in artifacts],
    }

    _write_text(out / "GITHUB_PUBLISH_COMMANDS.md", _render_publish_commands())
    _write_text(out / "RELEASE_NOTE_DRAFT.md", _render_release_note(payload))
    _write_text(out / "PUBLIC_LAUNCH_SUMMARY.md", _render_launch_summary(payload))
    _write_checksums(out, artifacts)
    payload["checksums_path"] = str(out / "SHA256SUMS.txt")

    (out / "publish_manifest.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    publish_zip = _zip_publish_pack(out)
    publish_artifact = _artifact(publish_zip, out, "Final public launch handoff ZIP")
    payload["publish_zip_path"] = str(publish_zip)
    payload["publish_zip_sha256"] = publish_artifact.sha256
    payload["artifacts"].append(asdict(publish_artifact))
    (out / "publish_manifest.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


__all__ = ["build_publish_prep", "inspect_zip_hygiene"]
