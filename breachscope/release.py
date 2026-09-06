"""Release metadata, packaging, and checksum helpers for BreachScope."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 fallback
    import tomli as tomllib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from zipfile import ZIP_DEFLATED, ZipFile


DEFAULT_EXCLUDES = (
    ".git/*",
    ".github/workflows/*.local.yml",
    ".pytest_cache/*",
    "__pycache__/*",
    "*/__pycache__/*",
    "*.pyc",
    "*.pyo",
    ".env",
    ".venv/*",
    "venv/*",
    "env/*",
    "ENV/*",
    "out/*",
    "out_*/*",
    "dist/*",
    "build/*",
    "*.egg-info/*",
    "*.sqlite",
    "*.db",
    "*.log",
    "*.jsonl",
    ".DS_Store",
)


@dataclass(frozen=True)
class ProjectMetadata:
    name: str
    version: str
    description: str
    python_requires: str
    generated_at: str
    git_sha: str | None = None
    git_tag: str | None = None
    build_number: str | None = None


@dataclass(frozen=True)
class ReleaseArtifact:
    path: str
    size_bytes: int
    sha256: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_pyproject(repo_root: Path) -> dict:
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return {}
    with pyproject.open("rb") as fh:
        return tomllib.load(fh)


def _git_output(repo_root: Path, args: list[str]) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=repo_root, stderr=subprocess.DEVNULL, text=True).strip() or None
    except Exception:
        return None


def get_project_metadata(repo_root: str | Path = ".") -> ProjectMetadata:
    """Return project metadata from pyproject plus CI/build environment."""
    root = Path(repo_root).resolve()
    project = _read_pyproject(root).get("project", {})
    return ProjectMetadata(
        name=str(project.get("name") or "breachscope"),
        version=str(os.getenv("BS_BUILD_VERSION") or project.get("version") or "0.0.0"),
        description=str(project.get("description") or "BreachScope DFIR console"),
        python_requires=str(project.get("requires-python") or ">=3.10"),
        generated_at=utc_now_iso(),
        git_sha=os.getenv("BS_BUILD_SHA") or _git_output(root, ["rev-parse", "--short", "HEAD"]),
        git_tag=os.getenv("BS_BUILD_TAG") or _git_output(root, ["describe", "--tags", "--exact-match"]),
        build_number=os.getenv("GITHUB_RUN_NUMBER") or os.getenv("BUILD_NUMBER"),
    )


def runtime_build_info(repo_root: str | Path = ".") -> dict:
    """Return runtime/build metadata suitable for API responses."""
    meta = get_project_metadata(repo_root)
    return {
        **asdict(meta),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "executable": sys.executable,
    }


def should_exclude(relative_path: str, patterns: Iterable[str] = DEFAULT_EXCLUDES) -> bool:
    rel = relative_path.replace("\\", "/").strip("/")
    if not rel:
        return True
    parts = rel.split("/")
    if any(part in {"__pycache__", ".pytest_cache"} for part in parts):
        return True
    return any(fnmatch.fnmatch(rel, pattern) for pattern in patterns)


def iter_release_files(repo_root: str | Path, patterns: Iterable[str] = DEFAULT_EXCLUDES) -> list[Path]:
    """Return deterministic source files for release ZIP creation."""
    root = Path(repo_root).resolve()
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if should_exclude(rel, patterns):
            continue
        files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def create_source_zip(repo_root: str | Path, output_path: str | Path, *, top_level_dir: str | None = None) -> ReleaseArtifact:
    root = Path(repo_root).resolve()
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    meta = get_project_metadata(root)
    top = top_level_dir or f"{meta.name}-{meta.version}"
    with ZipFile(output, "w", ZIP_DEFLATED) as zf:
        for path in iter_release_files(root):
            rel = path.relative_to(root).as_posix()
            zf.write(path, f"{top}/{rel}")
    return ReleaseArtifact(path=str(output), size_bytes=output.stat().st_size, sha256=sha256_file(output))


def write_checksums(artifacts: list[ReleaseArtifact], output_path: str | Path) -> ReleaseArtifact:
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{artifact.sha256}  {Path(artifact.path).name}" for artifact in artifacts]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ReleaseArtifact(path=str(output), size_bytes=output.stat().st_size, sha256=sha256_file(output))


def write_release_manifest(repo_root: str | Path, artifacts: list[ReleaseArtifact], output_path: str | Path) -> ReleaseArtifact:
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": asdict(get_project_metadata(repo_root)),
        "artifacts": [asdict(artifact) for artifact in artifacts],
        "release_checks": {
            "source_zip_created": any(Path(a.path).suffix == ".zip" for a in artifacts),
            "checksum_file_created": any(Path(a.path).name == "SHA256SUMS.txt" for a in artifacts),
        },
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return ReleaseArtifact(path=str(output), size_bytes=output.stat().st_size, sha256=sha256_file(output))


def build_release_bundle(repo_root: str | Path = ".", dist_dir: str | Path | None = None) -> dict:
    """Build a source release ZIP plus checksum and manifest files."""
    root = Path(repo_root).resolve()
    meta = get_project_metadata(root)
    dist = Path(dist_dir).resolve() if dist_dir else root / "dist"
    dist.mkdir(parents=True, exist_ok=True)

    zip_artifact = create_source_zip(root, dist / f"{meta.name}-{meta.version}-source.zip")
    checksums = write_checksums([zip_artifact], dist / "SHA256SUMS.txt")
    manifest = write_release_manifest(root, [zip_artifact, checksums], dist / "release_manifest.json")
    return {
        "metadata": asdict(meta),
        "artifacts": [asdict(zip_artifact), asdict(checksums), asdict(manifest)],
        "dist_dir": str(dist),
    }


def clean_dist(dist_dir: str | Path) -> None:
    dist = Path(dist_dir)
    if dist.exists():
        shutil.rmtree(dist)
