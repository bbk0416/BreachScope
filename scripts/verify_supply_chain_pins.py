#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ACTION_PINS = {
    "actions/checkout": (
        "11d5960a326750d5838078e36cf38b85af677262",
        "v4.4.0",
    ),
    "actions/setup-python": (
        "a26af69be951a213d495a4c3e4e4022e16d87065",
        "v5.6.0",
    ),
    "actions/upload-artifact": (
        "ea165f8d65b6e75b540449e92b4886f43607fa02",
        "v4.6.2",
    ),
    "docker/setup-buildx-action": (
        "8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
        "v3.12.0",
    ),
    "docker/build-push-action": (
        "10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
        "v6.19.2",
    ),
    "softprops/action-gh-release": (
        "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65",
        "v2.6.2",
    ),
}

DOCKER_BASE = (
    "python:3.11.16-slim-bookworm@"
    "sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91"
)

USES_RE = re.compile(
    r"(?m)^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)"
)


def verify_action_refs() -> list[str]:
    issues: list[str] = []
    workflow_dir = ROOT / ".github" / "workflows"

    seen: dict[str, int] = {name: 0 for name in ACTION_PINS}

    for path in sorted(workflow_dir.glob("*")):
        if not path.is_file() or path.suffix.casefold() not in {".yml", ".yaml"}:
            continue

        text = path.read_text(encoding="utf-8")
        for action, ref in USES_RE.findall(text):
            if action not in ACTION_PINS:
                issues.append(
                    f"{path.relative_to(ROOT)}: unapproved external action "
                    f"{action}@{ref}"
                )
                continue

            expected_sha, expected_version = ACTION_PINS[action]
            seen[action] += 1

            if ref != expected_sha:
                issues.append(
                    f"{path.relative_to(ROOT)}: {action} must be pinned to "
                    f"{expected_sha} ({expected_version}), got {ref}"
                )

    for action, count in seen.items():
        if count == 0:
            issues.append(f"expected action is not referenced: {action}")

    return issues


def _docker_base_ref(text: str) -> str:
    # Windows-authored source files may carry a UTF-8 BOM. Parse the Docker
    # instruction rather than comparing a raw first line so BOM/comments/
    # whitespace cannot create a false negative.
    normalized = text.lstrip("\ufeff")
    match = re.search(
        r"(?im)^\s*FROM\s+([^\s]+)(?:\s+AS\s+\S+)?\s*$",
        normalized,
    )
    return match.group(1).strip() if match else ""


def verify_dockerfile() -> list[str]:
    issues: list[str] = []
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8-sig")

    actual_base = _docker_base_ref(text)
    if actual_base != DOCKER_BASE:
        issues.append(
            "Dockerfile base must be exactly digest-pinned to "
            f"{DOCKER_BASE}; got {actual_base or '(missing FROM)'}"
        )

    return issues


def verify_dependabot() -> list[str]:
    issues: list[str] = []
    path = ROOT / ".github" / "dependabot.yml"
    if not path.exists():
        return [".github/dependabot.yml is missing"]

    text = path.read_text(encoding="utf-8")

    if 'package-ecosystem: "github-actions"' not in text:
        issues.append("Dependabot does not monitor GitHub Actions")
    if 'package-ecosystem: "docker"' not in text:
        issues.append("Dependabot does not monitor Docker")
    if text.count('interval: "weekly"') < 2:
        issues.append("Dependabot supply-chain updates must run weekly")

    return issues


def verify_workflow_permissions() -> list[str]:
    issues: list[str] = []
    workflow_dir = ROOT / ".github" / "workflows"

    for path in sorted(workflow_dir.glob("*")):
        if not path.is_file() or path.suffix.casefold() not in {".yml", ".yaml"}:
            continue

        text = path.read_text(encoding="utf-8")
        if not re.search(r"(?m)^permissions:\s*(?:\{\}\s*)?$", text):
            if not re.search(r"(?m)^permissions:\s*$", text):
                issues.append(
                    f"{path.relative_to(ROOT)} lacks explicit permissions"
                )

    return issues


def verify_repo_contract() -> list[str]:
    issues: list[str] = []
    issues.extend(verify_action_refs())
    issues.extend(verify_dockerfile())
    issues.extend(verify_dependabot())
    issues.extend(verify_workflow_permissions())
    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true")
    parser.parse_args()

    issues = verify_repo_contract()
    if issues:
        print("BreachScope supply-chain pin verification: FAIL")
        for issue in issues:
            print("[FAIL]", issue)
        return 1

    print("BreachScope supply-chain pin verification: PASS")
    print("GitHub Actions: immutable 40-character commit SHAs")
    print("Docker base: immutable sha256 index digest")
    print("Dependabot: weekly GitHub Actions + Docker monitoring")
    print("Workflow permissions: explicit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
