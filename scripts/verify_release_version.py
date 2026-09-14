#!/usr/bin/env python3
"""Fail closed when a release tag does not match pyproject.toml version."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def normalize_release_tag(tag: str) -> str:
    value = tag.strip()
    if value.startswith("v"):
        value = value[1:]
    if not value:
        raise ValueError("release tag is empty")
    return value


def read_project_version(repo_root: str | Path = ROOT) -> str:
    path = Path(repo_root) / "pyproject.toml"
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    version = str(data.get("project", {}).get("version", "")).strip()
    if not version:
        raise ValueError("project.version is missing from pyproject.toml")
    return version


def verify_release_version(tag: str, project_version: str) -> None:
    tagged_version = normalize_release_tag(tag)
    if tagged_version != project_version:
        raise ValueError(
            f"release tag/version mismatch: tag={tag!r} -> {tagged_version!r}, "
            f"pyproject={project_version!r}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify Git release tag against pyproject.toml version")
    parser.add_argument("--tag", required=True, help="Release tag, normally vX.Y.Z")
    parser.add_argument("--repo-root", default=str(ROOT), help="Repository root")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    version = read_project_version(args.repo_root)
    try:
        verify_release_version(args.tag, version)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"release version verified: tag={args.tag} package={version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
