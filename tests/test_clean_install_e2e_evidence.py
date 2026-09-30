from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "clean_install_e2e_20260930.yaml"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_clean_install_evidence_is_bound_to_current_sources() -> None:
    row = _row()
    assert row["schema"] == "breachscope.clean_install_e2e.v1"
    assert row["status"] == "PASS"
    assert row["environment"]["python_version"] == "3.11.9"
    assert row["environment"]["source_checkout_used_at_runtime"] is False

    for binding in row["source_binding"].values():
        assert _sha(ROOT / binding["path"]) == binding["sha256"]


def test_clean_install_evidence_covers_wheel_cli_and_web_runtime() -> None:
    result = _row()["result"]
    assert result["wheel_name"] == "breachscope-2.1.2-py3-none-any.whl"
    assert result["wheel_build"] == "PASS"
    assert result["fresh_venv"] == "PASS"
    assert result["wheel_install_with_dependencies"] == "PASS"
    assert result["installed_imports"] == "PASS"
    assert result["installed_version"] == "2.1.2"
    assert result["packaged_rule_files"] == 5
    assert result["packaged_templates"] == "PASS"
    assert result["demo_cli_exit"] == 0
    assert result["fastapi_health"] == "PASS"
    assert result["fastapi_readiness"] == "PASS"
    assert result["cleanup"] is True


def test_clean_install_claim_boundary_stays_narrow() -> None:
    claims = _row()["claim_boundary"]
    assert claims["clean_wheel_build_and_install_verified"] is True
    assert claims["fresh_venv_verified"] is True
    assert claims["packaged_runtime_assets_verified"] is True
    assert claims["demo_cli_verified"] is True
    assert claims["fastapi_health_verified"] is True
    assert claims["fastapi_readiness_verified"] is True
    assert claims["source_checkout_not_used_at_runtime"] is True
    assert claims["windows_python_3_11_verified"] is True
    assert claims["linux_clean_install"] == "PASS"
    assert claims["macos_clean_install"] == "PASS"
    assert claims["offline_dependency_install"] == "NOT_TESTED"
    assert claims["public_release_asset_download_path"] == "NOT_TESTED"
    assert claims["fresh_machine_without_cached_packages"] == "NOT_TESTED"

def test_cross_platform_clean_install_ci_is_recorded() -> None:
    ci = _row()["cross_platform_ci"]
    assert ci["pull_request"] == 353
    assert ci["workflow"] == "CI"
    assert ci["run_id"] == 36755495797
    assert ci["run_number"] == 510
    assert ci["head_repo_commit"] == (
        "13aa7ca9215939e4160d3632a81af54f8c6f073f"
    )

    ubuntu = ci["ubuntu"]
    assert ubuntu == {
        "job_id": 110024576797,
        "runner": "ubuntu-latest",
        "setup_python": "3.11.16",
        "actual_python": "3.11.16",
        "conclusion": "SUCCESS",
        "verifier_status": "PASS",
        "cleanup": True,
    }

    macos = ci["macos"]
    assert macos == {
        "job_id": 110024576368,
        "runner": "macos-15-intel",
        "setup_python": "3.11",
        "actual_python": "3.11.9",
        "conclusion": "SUCCESS",
        "verifier_status": "PASS",
        "cleanup": True,
    }
