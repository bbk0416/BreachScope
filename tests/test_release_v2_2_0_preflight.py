from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "release_v2_2_0_preflight_20261001.yaml"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_v2_2_0_preflight_is_bound_to_release_sources() -> None:
    row = _row()
    assert row["schema"] == "breachscope.release_v2_2_0_preflight.v1"
    assert row["status"] == "LOCAL_PREFLIGHT_PASS_CROSS_PLATFORM_PENDING"
    assert row["release_version"] == "2.2.0"
    assert row["release_tag"] == "v2.2.0"

    for binding in row["source_binding"].values():
        assert _sha(ROOT / binding["path"]) == binding["sha256"]


def test_v2_2_0_windows_final_wheel_clean_install_passed() -> None:
    row = _row()["windows_clean_install"]
    assert row["python_version"] == "3.11.9"
    assert row["wheel_name"] == "breachscope-2.2.0-py3-none-any.whl"
    assert row["wheel_build"] == "PASS"
    assert row["fresh_venv"] == "PASS"
    assert row["wheel_install_with_dependencies"] == "PASS"
    assert row["installed_imports"] == "PASS"
    assert row["installed_version"] == "2.2.0"
    assert row["packaged_rule_files"] == 5
    assert row["packaged_templates"] == "PASS"
    assert row["demo_cli_exit"] == 0
    assert row["fastapi_health"] == "PASS"
    assert row["fastapi_readiness"] == "PASS"
    assert row["source_checkout_used_at_runtime"] is False
    assert row["cleanup"] is True


def test_v2_2_0_release_version_is_consistent_in_public_docs() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["version"] == "2.2.0"

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    quickstart = (ROOT / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
    api_docs = (ROOT / "docs" / "API_DOCUMENTATION.md").read_text(encoding="utf-8")
    changelog = (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")
    release_notes = (ROOT / "docs" / "RELEASE_NOTES_2_2_0.md").read_text(
        encoding="utf-8"
    )

    assert "breachscope-2.2.0-py3-none-any.whl" in readme
    assert "breachscope-2.2.0-py3-none-any.whl" in quickstart
    assert '"version": "2.2.0"' in api_docs
    assert "## 2.2.0 - 2026-10-01" in changelog
    assert release_notes.startswith("# BreachScope v2.2.0")
    assert not re.search(r"breachscope-2\.1\.2-py3-none-any\.whl", readme)
    assert not re.search(r"breachscope-2\.1\.2-py3-none-any\.whl", quickstart)


def test_v2_2_0_release_is_not_claimed_published_before_tag() -> None:
    row = _row()
    assert row["final_release_ci"]["ci"] == "PENDING_PR_CI"
    assert row["final_release_ci"]["ubuntu_clean_install"] == "PENDING_PR_CI"
    assert row["final_release_ci"]["macos_clean_install"] == "PENDING_PR_CI"
    assert row["release_state"]["tag_created"] is False
    assert row["release_state"]["github_release_published"] is False
    assert row["release_state"]["release_workflow_executed_for_v2_2_0"] is False
    assert row["claim_boundary"]["github_release_v2_2_0"] == "NOT_PUBLISHED"
    assert row["claim_boundary"]["production_detection_accuracy"] == "NOT_CLAIMED"
    assert row["claim_boundary"]["production_detection_recall"] == "NOT_CLAIMED"
    assert row["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
