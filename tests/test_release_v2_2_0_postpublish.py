from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "release_v2_2_0_postpublish_20261001.yaml"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_v2_2_0_postpublish_evidence_is_source_bound() -> None:
    row = _row()
    assert row["schema"] == "breachscope.release_v2_2_0_postpublish.v1"
    assert row["status"] == "PUBLISHED_AND_PUBLIC_DOWNLOAD_VERIFIED"
    assert row["release_version"] == "2.2.0"
    assert row["release_tag"] == "v2.2.0"
    assert row["tag_commit"] == "c08266e5c57e8e9cbf050cfc46f94c38482924a3"
    for binding in row["source_binding"].values():
        assert _sha(ROOT / binding["path"]) == binding["sha256"]


def test_v2_2_0_release_workflow_published_exact_tag_build() -> None:
    row = _row()
    run = row["tag_release_execution"]
    assert run["execution_mode"] == "workflow_dispatch_on_tag_ref"
    assert run["run_id"] == 36805575766
    assert run["job_id"] == 110189087573
    assert run["ref"] == "v2.2.0"
    assert run["head_sha"] == row["tag_commit"]
    assert run["conclusion"] == "SUCCESS"
    assert run["verify_release_tag_matches_package_version"] == "SUCCESS"
    assert run["test_before_release"] == "SUCCESS"
    assert run["publish_github_release"] == "SUCCESS"

    manifest = row["release_manifest"]
    assert manifest["git_sha"] == row["tag_commit"]
    assert manifest["git_tag"] == "v2.2.0"
    assert manifest["build_number"] == "5"


def test_v2_2_0_release_assets_are_complete_and_hash_locked() -> None:
    row = _row()
    assets = {item["name"]: item for item in row["release_assets"]}
    assert set(assets) == {
        "breachscope-2.2.0-py3-none-any.whl",
        "breachscope-2.2.0-source.zip",
        "breachscope-2.2.0.tar.gz",
        "SHA256SUMS.txt",
        "release_manifest.json",
    }
    assert assets["breachscope-2.2.0-py3-none-any.whl"]["sha256"] == (
        "259425afca4d5381550b74ed116ab43306ab5eb6d0b93539aba0f3cea7f133a5"
    )
    assert assets["breachscope-2.2.0-source.zip"]["sha256"] == (
        "d9528fb3d52a9cde78312290c6bfb5d9a8c2ba9713a082833bdd9e645e39e27b"
    )
    assert assets["breachscope-2.2.0.tar.gz"]["sha256"] == (
        "a677f0be59004cb8ff391a3c023243f34640e667da0f2aff10d217ed313e6160"
    )
    assert assets["SHA256SUMS.txt"]["sha256"] == (
        "b6dd3233d328331d41481070d5795abe9de99e62726b8cc1be551a2d1166c924"
    )
    assert assets["release_manifest.json"]["sha256"] == (
        "6be74dcd135a44064a793086ac1e4f6967ef5e34ae12b7af3cca8a826641d70e"
    )


def test_v2_2_0_public_download_and_runtime_smoke_passed() -> None:
    check = _row()["public_download_verification"]
    assert check["method"] == "unauthenticated_https_curl"
    assert check["all_five_release_assets_downloaded"] is True
    assert check["manifest_and_checksum_hashes_match"] is True
    assert check["wheel_python_version"] == "3.11.9"
    assert check["fresh_venv"] == "PASS"
    assert check["public_wheel_install"] == "PASS"
    assert check["installed_version"] == "2.2.0"
    assert check["installed_imports"] == "PASS"
    assert check["packaged_rule_files"] == 5
    assert check["packaged_templates"] == "PASS"
    assert check["demo_cli_exit"] == 0
    assert check["fastapi_health"] == "PASS"
    assert check["fastapi_readiness"] == "PASS"
    assert check["source_checkout_used_at_runtime"] is False
    assert check["cleanup"] is True


def test_v2_2_0_postpublish_claims_remain_bounded() -> None:
    row = _row()
    release = row["github_release"]
    assert release["draft"] is False
    assert release["prerelease"] is False
    assert release["public"] is True

    signing = row["release_signing"]
    assert signing["signing_mechanism_implemented"] is True
    assert signing["workflow_log_state"] == "disabled"
    assert signing["detached_signature_generated"] is False
    assert signing["detached_signature_asset_published"] is False

    claims = row["claim_boundary"]
    assert claims["github_release_v2_2_0"] == "PUBLISHED"
    assert claims["public_release_asset_download_path"] == "PASS"
    assert claims["public_wheel_clean_install_and_runtime_smoke"] == "PASS"
    assert claims["detached_release_signature_for_v2_2_0"] == "NOT_PUBLISHED"
    assert claims["production_detection_accuracy"] == "NOT_CLAIMED"
    assert claims["production_detection_precision"] == "NOT_CLAIMED"
    assert claims["production_detection_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
