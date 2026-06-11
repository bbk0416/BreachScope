import json
import zipfile
from pathlib import Path

from breachscope.release import (
    build_release_bundle,
    get_project_metadata,
    iter_release_files,
    sha256_file,
    should_exclude,
)


def _minimal_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        """
[project]
name = "breachscope-test"
version = "9.9.9"
description = "release test"
requires-python = ">=3.10"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text("# test\n", encoding="utf-8")
    (repo / "breachscope").mkdir()
    (repo / "breachscope" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__" / "bad.pyc").write_bytes(b"bad")
    (repo / "out").mkdir()
    (repo / "out" / "report.json").write_text("{}", encoding="utf-8")
    (repo / ".env").write_text("SECRET=bad\n", encoding="utf-8")
    return repo


def test_release_file_filter_excludes_runtime_and_secret_files(tmp_path):
    repo = _minimal_repo(tmp_path)
    files = {p.relative_to(repo).as_posix() for p in iter_release_files(repo)}
    assert "README.md" in files
    assert "pyproject.toml" in files
    assert "breachscope/__init__.py" in files
    assert ".env" not in files
    assert "out/report.json" not in files
    assert "__pycache__/bad.pyc" not in files
    assert should_exclude("dist/breachscope.zip") is True


def test_build_release_bundle_creates_zip_manifest_and_checksums(tmp_path):
    repo = _minimal_repo(tmp_path)
    result = build_release_bundle(repo, repo / "dist")

    artifact_names = {Path(item["path"]).name for item in result["artifacts"]}
    assert "breachscope-test-9.9.9-source.zip" in artifact_names
    assert "SHA256SUMS.txt" in artifact_names
    assert "release_manifest.json" in artifact_names

    manifest_path = repo / "dist" / "release_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["metadata"]["name"] == "breachscope-test"
    assert manifest["metadata"]["version"] == "9.9.9"
    assert manifest["release_checks"]["source_zip_created"] is True
    assert manifest["release_checks"]["checksum_file_created"] is True

    zip_path = repo / "dist" / "breachscope-test-9.9.9-source.zip"
    checksums = (repo / "dist" / "SHA256SUMS.txt").read_text(encoding="utf-8")
    assert sha256_file(zip_path) in checksums
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert "breachscope-test-9.9.9/README.md" in names
    assert "breachscope-test-9.9.9/.env" not in names
    assert "breachscope-test-9.9.9/out/report.json" not in names


def test_project_metadata_honors_build_environment(tmp_path, monkeypatch):
    repo = _minimal_repo(tmp_path)
    monkeypatch.setenv("BS_BUILD_VERSION", "v16.0.0")
    monkeypatch.setenv("BS_BUILD_SHA", "abc123")
    monkeypatch.setenv("BS_BUILD_TAG", "v16.0.0")
    meta = get_project_metadata(repo)
    assert meta.version == "v16.0.0"
    assert meta.git_sha == "abc123"
    assert meta.git_tag == "v16.0.0"
