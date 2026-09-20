from __future__ import annotations

import hashlib
import importlib.util
import io
import tarfile
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_28_real_evtx_ingest_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_28_real_evtx_ingest_benchmark.py"

RUNNER_SHA = "126b5e33fc9e1ec5485198d4f1a3100672e2ef62c7305596577df3d26c974ac1"
RULE_HASH = "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
ARCHIVE_SHA = "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def _text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _runner_module():
    spec = importlib.util.spec_from_file_location("p2_28_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p2_28_contract_binds_current_product_and_exact_real_evtx_source() -> None:
    row = _load()
    assert row["status"] == "PREREGISTERED_BEFORE_CANONICAL_EXECUTION"

    product = row["product"]
    assert product["repo_commit"] == "7dd6da1069f4d5a29de5fd367fd45fdee24d70d6"
    assert product["rules_tree_sha256"] == RULE_HASH
    assert product["rule_file_count"] == 5
    assert product["rule_count"] == 68
    assert product["rules_are_not_evaluated"] is True

    source = row["source"]
    assert source["asset_name"] == "win10-client.tgz"
    assert source["asset_size_bytes"] == 70_844_052
    assert source["asset_sha256"] == ARCHIVE_SHA
    assert source["expected_source_evtx_files_total"] == 352
    assert source["expected_source_evtx_files_with_events"] == 97
    assert source["expected_reference_events"] == 766_623
    assert source["reused_for_performance_only"] is True
    assert source["fresh_detection_evaluation"] is False


def test_p2_28_runner_hash_and_real_product_path_are_preregistered() -> None:
    row = _load()
    assert row["runner"]["sha256"] == RUNNER_SHA
    assert _text_sha256(RUNNER) == RUNNER_SHA
    assert row["runner"]["python_major_minor"] == "3.11"
    assert row["runner"]["operating_system"] == "Windows"

    measurement = row["measurement"]
    assert measurement["product_path"] == [
        "safe_extract_evtx_from_bound_archive",
        "breachscope.ingest.convert_evtx_dir",
        "breachscope.pipeline.Pipeline.collect_events",
    ]
    assert measurement["detection_stage_executed"] is False
    assert measurement["correlation_stage_executed"] is False
    assert measurement["scenario_stage_executed"] is False
    assert measurement["report_stage_executed"] is False


def test_p2_28_accounting_gate_fails_closed_before_performance_claim() -> None:
    row = _load()
    gate = row["accounting_gate"]
    assert gate["exact_source_evtx_files_required"] == 352
    assert gate["exact_normalized_events_required"] == 766_623
    assert gate["source_file_count_mismatch_status"] == "FAILED_ACCOUNTING_MISMATCH"
    assert gate["normalized_event_count_mismatch_status"] == "FAILED_ACCOUNTING_MISMATCH"
    assert gate["throughput_claim_if_accounting_mismatch"] == "NOT_CLAIMED"
    assert gate["performance_success_requires_accounting_match"] is True


def test_p2_28_protocol_is_first_run_only_and_does_not_run_detection() -> None:
    protocol = _load()["protocol"]
    assert protocol["contract_must_merge_before_canonical_execution"] is True
    assert protocol["permanent_lock_acquired_before_archive_verification"] is True
    assert protocol["duplicate_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_canonical_result_for_better_numbers"] is False
    assert protocol["source_accounting_mismatch_fails_performance_claim"] is True
    assert protocol["detection_must_not_execute"] is True
    assert protocol["p2_23b_canonical_result_modified"] is False
    assert protocol["p2_26c_canonical_result_modified"] is False


def test_p2_28_safe_extract_rejects_tar_traversal(tmp_path: Path) -> None:
    module = _runner_module()
    archive = tmp_path / "bad.tgz"
    payload = b"not-an-evtx"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("../escape.evtx")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    with pytest.raises(RuntimeError, match="unsafe archive member"):
        module.safe_extract_evtx(archive, tmp_path / "out")


def test_p2_28_claim_boundary_stays_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["real_evtx_ingest_performance"] == "NOT_YET_MEASURED"
    assert claim["production_capacity"] == "NOT_CLAIMED"
    assert claim["enterprise_scale_readiness"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
    assert claim["cross_tool_speed_comparison"] == "NOT_CLAIMED"
    assert claim["detection_accuracy"] == "NOT_EVALUATED"
    assert claim["benign_fpr"] == "NOT_EVALUATED"
