from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FAILURE = ROOT / "external_baseline" / "p2_35l_current_rulepack_fresh_exact_bytes_failure.yaml"
RAW = ROOT / "external_baseline" / "results" / "p2_35l_a0569ca" / "result.json"
LOCK = ROOT / "external_baseline" / "locks" / "P2_35L_CURRENT_RULEPACK_FRESH_EXACT_BYTES.lock"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row() -> dict:
    return yaml.safe_load(FAILURE.read_text(encoding="utf-8"))


def test_p2_35l_failure_artifacts_are_exact() -> None:
    row = _row()
    assert row["status"] == "FAILED_CANONICAL_NO_RETRY"
    assert RAW.stat().st_size == 72_572
    assert LOCK.stat().st_size == 114
    assert _sha(RAW) == "b7e7ca552d394a6f7f2e325e02b5094131fd72c2777db1c6fa043599dd123a64"
    assert _sha(LOCK) == "df991aa55243b41bdc7ae5e02cc095e0d18a516f4641067cf9c2fb552fb987a5"


def test_p2_35l_failed_during_benign_progress_persistence() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = _row()["execution"]
    assert raw["status"] == "failed"
    assert "PermissionError" in raw["error"]
    assert "result.json.tmp" in raw["error"]
    assert row["failure_class"] == "EVALUATOR_OUTPUT_PERSISTENCE_PERMISSION_ERROR"
    assert row["failure_stage"] == "BENIGN_MEMBER_PROGRESS_ATOMIC_WRITE"
    assert row["product_or_rules_failure"] is False
    assert row["source_identity_failure"] is False


def test_p2_35l_attack_completed_but_combined_revalidation_did_not() -> None:
    row = _row()
    run = row["execution"]
    assert run["attack_phase_completed"] is True
    assert run["attack_fixture_count"] == 6
    assert run["attack_hits"] == 4
    assert run["attack_misses"] == 2
    assert run["attack_errors"] == 0
    assert run["benign_member_inventory_count"] == 330
    assert run["benign_processed_member_count_before_failure"] == 61
    assert run["benign_summary_completed"] is False
    claim = row["interpretation"]
    assert claim["attack_partial_result_is_fresh_attack_revalidation_claim"] is False
    assert claim["benign_fresh_revalidation_completed"] is False
    assert claim["combined_fresh_revalidation_completed"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"


def test_p2_35l_analysis_id_is_permanently_retired() -> None:
    row = _row()
    assert row["execution"]["canonical_execution_started"] is True
    assert row["execution"]["same_analysis_id_retry_allowed"] is False
    assert row["execution"]["duplicate_execution_performed"] is False
    assert row["next_analysis"]["analysis_id"] == "p2-35m-current-rulepack-fresh-source-revalidation-v1"
