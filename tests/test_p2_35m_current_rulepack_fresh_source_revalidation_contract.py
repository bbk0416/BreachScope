from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "p2_35m_current_rulepack_fresh_source_revalidation_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_35m_current_rulepack_fresh_source_revalidation.py"
FAILURE = ROOT / "external_baseline" / "p2_35l_current_rulepack_fresh_exact_bytes_failure.yaml"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _module():
    spec = importlib.util.spec_from_file_location("p2_35m_contract_test", RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_p2_35m_identity_predecessor_and_product() -> None:
    row = _load()
    assert row["analysis_id"] == "p2-35m-current-rulepack-fresh-source-revalidation-v1"
    assert row["status"] == "PREREGISTERED_NOT_RUN"
    assert row["preregistration"]["base_main_commit"] == "a84e535a3382a414bdbb2eb4c00dd99a2c387060"
    assert row["preregistration"]["p2_35l_same_analysis_id_retry_forbidden"] is True
    assert row["preregistration"]["predecessor_failure_record_in_same_pr"] is False
    assert row["preregistration"]["predecessor_failure_main_commit"] == "a84e535a3382a414bdbb2eb4c00dd99a2c387060"
    assert row["preregistration"]["predecessor_failure"].endswith(
        "p2_35l_current_rulepack_fresh_exact_bytes_failure.yaml"
    )
    assert row["frozen_product"]["rule_count"] == 69
    assert row["frozen_product"]["rules_tree_sha256"] == (
        "1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7"
    )
    failure = yaml.safe_load(FAILURE.read_text(encoding="utf-8"))
    assert failure["status"] == "FAILED_CANONICAL_NO_RETRY"


def test_p2_35m_runner_hash_and_output_retry_are_fixed() -> None:
    row = _load()["runner"]
    digest = hashlib.sha256(
        RUNNER.read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert row["sha256"] == digest
    assert row["sha256"] == (
        "f480f65089d1470f157e9e733514c2caf49df9acd3a452f490596cbd1420d253"
    )
    assert row["product_repo_mode"] == "SEPARATE_FROZEN_GIT_WORKTREE"
    assert row["atomic_output_strategy"] == (
        "PID_SCOPED_TEMP_FILE_PLUS_PERMISSIONERROR_RETRY"
    )
    assert row["atomic_replace_retry_exception"] == "PermissionError"
    assert row["atomic_replace_retry_delays_seconds"] == [
        0.05,
        0.1,
        0.2,
        0.4,
        0.8,
        1.6,
    ]
    assert row["detector_semantics_changed_by_retry"] is False


def test_p2_35m_attack_source_is_unused_yamato_original_bundle() -> None:
    row = _load()["attack_revalidation"]
    source = row["source"]
    assert source["repository"] == "Yamato-Security/hayabusa-sample-evtx"
    assert source["pinned_commit"] == (
        "0845333ecb4afcf64c55c6e10946383f168f308c"
    )
    assert source["readme_git_blob_sha1"] == (
        "36d08b56243e856cb26293fd2add8e790df1a326"
    )
    assert source["source_family_previously_used_by_breachscope"] is False
    assert (
        row["freshness"]["selected_exact_bytes_previously_detector_evaluated"]
        is False
    )
    assert row["freshness"]["attack_event_contents_parsed_for_selection"] is False
    assert row["selection_policy"]["all_selector_matches_selected"] is True
    assert row["selection_policy"]["selected_fixture_count"] == 10
    assert len(row["datasets"]) == 10
    assert all(
        x["source_path"].startswith("YamatoSecurity/")
        for x in row["datasets"]
    )
    assert all(
        len(x["sha256"]) == 64 and len(x["git_blob_sha1"]) == 40
        for x in row["datasets"]
    )
    assert [
        x["expected_technique"] for x in row["datasets"]
    ].count("T1210") == 3


def test_p2_35m_selector_is_metadata_only_and_deterministic() -> None:
    m = _module()
    rows = m.selected_attack_source_paths(
        [
            "YamatoSecurity/Persistence/T1197_BitsClient.evtx",
            "YamatoSecurity/Persistence/SharpEventPersistHiddenShellcode.evtx",
            "YamatoSecurity/Sysmon/Sysmon-27-BlockExeWrite_AbusingCertutil.evtx",
            "YamatoSecurity/LateralMovement/T1210_Zerologon_Sysmon.evtx",
            "EVTX-ATTACK-SAMPLES/Execution/T9999_NotYamato.evtx",
        ]
    )
    assert rows == [
        "YamatoSecurity/LateralMovement/T1210_Zerologon_Sysmon.evtx",
        "YamatoSecurity/Persistence/T1197_BitsClient.evtx",
    ]


def test_p2_35m_benign_archive_is_unused_and_not_downloaded_premerge() -> None:
    row = _load()["benign_revalidation"]
    assert row["archive"] == {
        "asset_name": "win2022-ad.tgz",
        "size_bytes": 65_991_035,
        "sha256": (
            "dde89557c8dd19756d1fb4797f566aaa94509847c2740968bf04b5bea0b34ec1"
        ),
        "digest_source": "GITHUB_RELEASE_V0_8_4_ASSET_METADATA",
    }
    fresh = row["freshness"]
    assert fresh["selected_archive_previously_detector_evaluated"] is False
    assert fresh["archive_downloaded_before_contract_merge"] is False
    assert fresh["archive_inventory_before_contract_merge"] is False
    assert fresh["event_contents_parsed_before_contract_merge"] is False
    assert (
        row["member_selection_policy"]["post_inventory_member_dropping_allowed"]
        is False
    )


def test_p2_35m_protocol_and_claim_boundary_are_narrow() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["one_canonical_execution_only"] is True
    assert protocol["global_lock_before_source_verification"] is True
    assert protocol["same_analysis_id_retry_allowed"] is False
    assert protocol["result_acceptance_depends_on_measurement_value"] is False
    claim = row["claim_boundary"]
    assert claim["attack_source_family_previously_used_by_breachscope"] is False
    assert claim["benign_source_family_previously_used_by_breachscope"] is True
    assert claim["combined_independent_source_family_holdout"] is False
    assert claim["attack_fixture_hit_rate_is_event_level_recall"] is False
    assert (
        claim["source_path_expected_technique_match_is_event_level_recall"]
        is False
    )
    assert claim["production_accuracy"] == "NOT_CLAIMED"


def test_p2_35m_lock_precedes_source_verification_and_inventory() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    body = source[source.index("def run(args: argparse.Namespace)") :]
    lock = body.index("acquire_global_lock(lock)")
    attack = body.index("verify_attack_repo(")
    benign = body.index("verify_benign_archive(")
    run_benign = body.index("run_benign_revalidation(")
    assert lock < attack < run_benign
    assert lock < benign < run_benign
    assert "--attack-repo" in source


def test_p2_35m_load_product_resolves_from_supplied_repo(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "product"
    (fake / "breachscope").mkdir(parents=True)
    (fake / "scripts").mkdir(parents=True)
    (fake / "breachscope" / "__init__.py").write_text("", encoding="utf-8")
    (fake / "scripts" / "__init__.py").write_text("", encoding="utf-8")
    (fake / "breachscope" / "analyzer.py").write_text(
        "def apply_rules(*args, **kwargs):\n    return []\n",
        encoding="utf-8",
    )
    (fake / "breachscope" / "ingest.py").write_text(
        "def _extract_from_xml(xml):\n    return {}\n",
        encoding="utf-8",
    )
    (fake / "breachscope" / "rules.py").write_text(
        "def load_rules(path):\n    return []\n",
        encoding="utf-8",
    )
    (fake / "breachscope" / "schemas.py").write_text(
        "class Event:\n    pass\n",
        encoding="utf-8",
    )
    (fake / "scripts" / "evaluate_external_holdout.py").write_text(
        "def rules_tree_hash(path):\n    return ('fake', 5)\n",
        encoding="utf-8",
    )
    code = f"""
import importlib.util
from pathlib import Path
runner=Path(r"{RUNNER}")
product=Path(r"{fake}")
spec=importlib.util.spec_from_file_location("m", runner)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
a,p,l,E,h=m.load_product(product)
for value in [
    a.__code__.co_filename,
    p.__code__.co_filename,
    l.__code__.co_filename,
    h.__code__.co_filename,
]:
    print(Path(value).resolve())
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    for line in completed.stdout.splitlines():
        assert Path(line).resolve().is_relative_to(fake.resolve())


def test_p2_35m_execution_not_started() -> None:
    assert _load()["execution_state"] == {
        "canonical_execution_started": False,
        "attack_detector_run": False,
        "benign_detector_run": False,
        "result_observed": False,
    }
