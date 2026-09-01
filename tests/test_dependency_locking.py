from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_dependency_locks.py"


def _module():
    spec = importlib.util.spec_from_file_location(
        "breachscope_verify_dependency_locks",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_dependency_lock_contract_passes():
    module = _module()
    assert module.verify_repo_contract() == []


def test_all_supported_python_locks_are_exact_and_hashed():
    module = _module()

    assert set(module.LOCKS) == {"310", "311", "312"}

    for path in module.LOCKS.values():
        assert path.exists()
        assert module.verify_lock(path) == []
        text = path.read_text(encoding="utf-8")
        assert "==" in text
        assert "--hash=sha256:" in text


def test_reference_python_runtime_is_explicit():
    assert (ROOT / ".python-version").read_text(
        encoding="utf-8"
    ).strip() == "3.11.16"


def test_ci_uses_exact_patch_versions_and_hashed_locks():
    text = (ROOT / ".github/workflows/ci.yml").read_text(
        encoding="utf-8"
    )
    for version in ("3.10.21", "3.11.16", "3.12.14"):
        assert version in text
    assert "requirements-lock-py" in text
    assert "--require-hashes" in text


def test_release_and_docker_reuse_locked_build_tools():
    release = (ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert 'python-version: "3.11.16"' in release
    assert "requirements-lock-py311.txt" in release
    assert "python -m build --no-isolation" in release

    assert "FROM python:3.11.16-slim-bookworm" in dockerfile
    assert "requirements-lock-py311.txt" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "--no-build-isolation" in dockerfile
