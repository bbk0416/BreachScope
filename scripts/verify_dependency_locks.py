#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LOCKS = {
    "310": ROOT / "requirements-lock-py310.txt",
    "311": ROOT / "requirements-lock-py311.txt",
    "312": ROOT / "requirements-lock-py312.txt",
}

REQUIRED_PACKAGES = {
    "jinja2",
    "pyyaml",
    "pysigma",
    "fastapi",
    "uvicorn",
    "python-multipart",
    "python-evtx",
    "pytest",
    "httpx",
    "build",
    "reportlab",
    "setuptools",
    "wheel",
}

PACKAGE_LINE_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)(?:\s*;\s*.+)?(?:\s*\\)?$"
)


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        if line[:1].isspace():
            if current:
                current.append(stripped)
            continue

        if current:
            blocks.append(" ".join(current))
        current = [stripped]

    if current:
        blocks.append(" ".join(current))

    return blocks


def verify_lock(path: Path) -> list[str]:
    if not path.exists():
        return [f"missing lock: {path.name}"]

    issues: list[str] = []
    packages: set[str] = set()
    blocks = requirement_blocks(
        path.read_text(encoding="utf-8-sig")
    )

    if len(blocks) < 15:
        issues.append(
            f"{path.name}: suspiciously small lock ({len(blocks)} entries)"
        )

    for block in blocks:
        lower = block.casefold()

        if lower.startswith((
            "--index-url",
            "--extra-index-url",
            "--find-links",
        )):
            issues.append(
                f"{path.name}: embedded index configuration is not allowed"
            )
            continue

        if " @ " in block or "git+" in lower:
            issues.append(
                f"{path.name}: direct URL/VCS dependency is not allowed: "
                f"{block}"
            )
            continue

        head = block.split(" --hash=", 1)[0].strip()
        if head.endswith("\\"):
            head = head[:-1].rstrip()

        match = PACKAGE_LINE_RE.match(head)
        if not match:
            issues.append(
                f"{path.name}: dependency is not exact-pinned: {head}"
            )
            continue

        packages.add(normalize_name(match.group(1)))

        if "--hash=sha256:" not in block:
            issues.append(
                f"{path.name}: exact dependency lacks SHA-256 hash: {head}"
            )

    missing = sorted(
        package
        for package in REQUIRED_PACKAGES
        if normalize_name(package) not in packages
    )
    if missing:
        issues.append(
            f"{path.name}: missing required direct packages: "
            + ", ".join(missing)
        )

    return issues


def verify_repo_contract() -> list[str]:
    issues: list[str] = []

    for path in LOCKS.values():
        issues.extend(verify_lock(path))

    version_file = ROOT / ".python-version"
    if not version_file.exists():
        issues.append(".python-version is missing")
    elif version_file.read_text(encoding="utf-8").strip() != "3.11.16":
        issues.append(".python-version must be exactly 3.11.16")

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if '"setuptools>=61.0"' not in pyproject:
        issues.append("dev extra does not include setuptools")
    if '"wheel"' not in pyproject:
        issues.append("dev extra does not include wheel")

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for version in ("3.10.21", "3.11.16", "3.12.14"):
        if version not in ci:
            issues.append(f"CI missing exact Python runtime {version}")
    if "requirements-lock-py" not in ci:
        issues.append("CI does not select a per-Python lock")
    if "--require-hashes" not in ci:
        issues.append("CI does not enforce lock hashes")

    release = (ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    if 'python-version: "3.11.16"' not in release:
        issues.append("release workflow does not pin Python 3.11.16")
    if "requirements-lock-py311.txt" not in release:
        issues.append("release workflow does not consume py311 lock")
    if "--require-hashes" not in release:
        issues.append("release workflow does not enforce lock hashes")
    if "python -m build --no-isolation" not in release:
        issues.append("release build does not reuse the locked build tools")

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if "FROM python:3.11.16-slim-bookworm" not in dockerfile:
        issues.append("Dockerfile does not pin Python patch/base variant")
    if "requirements-lock-py311.txt" not in dockerfile:
        issues.append("Dockerfile does not consume py311 lock")
    if "--require-hashes" not in dockerfile:
        issues.append("Dockerfile does not enforce lock hashes")
    if "--no-build-isolation" not in dockerfile:
        issues.append(
            "Dockerfile editable install does not reuse locked build tools"
        )

    compile_script = (
        ROOT / "scripts" / "compile_dependency_locks.py"
    ).read_text(encoding="utf-8")
    if 'UV_VERSION = "0.12.8"' not in compile_script:
        issues.append("lock compiler does not declare uv 0.12.8")
    if 'TARGET_PLATFORM = "x86_64-unknown-linux-gnu"' not in compile_script:
        issues.append("lock compiler target platform is not explicit")
    if 'EXCLUDE_NEWER = "2026-09-01T00:00:00Z"' not in compile_script:
        issues.append("lock compiler dependency cutoff is not explicit")

    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true")
    parser.parse_args()

    issues = verify_repo_contract()

    if issues:
        print("BreachScope dependency lock verification: FAIL")
        for issue in issues:
            print("[FAIL]", issue)
        return 1

    print("BreachScope dependency lock verification: PASS")
    print("Locks: py310, py311, py312")
    print("Target platform: x86_64-unknown-linux-gnu")
    print("All locked dependencies are exact-pinned with SHA-256 hashes.")
    print("CI/release/Docker consume the committed locks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
