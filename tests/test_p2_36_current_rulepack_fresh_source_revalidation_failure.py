from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FAILURE = (
    ROOT
    / "external_baseline"
    / "p2_36_current_rulepack_fresh_source_revalidation_failure.yaml"
)
RAW = ROOT / "external_baseline" / "results" / "p2_36_fe62c0c" / "result.json"
LOCK = (
    ROOT
    / "external_baseline"
    / "locks"
    / "P2_36_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row() -> dict:
    return yaml.safe_load(FAILURE.read_text(encoding="utf-8"))


def test_p2_36_failure_artifacts_are_exact() -> None:
    row = _row()
    assert row["status"] == "FAILED_CANONICAL_NO_RETRY"
    assert RAW.stat().st_size == 7_692
    assert LOCK.stat().st_size == 121
    assert _sha(RAW) == (
        "d5ea35d6dcbddb9ab2348ec2d66c119e5729fd3f6a87080da55fc465f538328a"
    )
    assert _sha(LOCK) == (
        "8cb476cb7f1fd124a38f2ef2375f69b6a7d84cd8916a39b0a4ff3adf30686fb1"
    )


def test_p2_36_failed_on_first_empty_benign_channel() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = _row()["execution"]
    assert raw["status"] == "failed"
    assert raw["error"] == (
        "RuntimeError: EVTX parsed zero events: 00000_9bd6bccacaa4b3e0.evtx"
    )
    assert run["failure_class"] == "EVALUATOR_EMPTY_EVTX_FATAL_POLICY"
    assert run["failure_stage"] == "BENIGN_FIRST_MEMBER_SCORING"
    assert run["product_or_rules_failure"] is False
    assert run["source_identity_failure"] is False
    assert run["source_preflight_completed"] is True
    members = raw["benign_revalidation"]["members"]
    assert len(members) == 1
    assert members[0]["name"] == (
        "win2022-0-20348-azure/AD FS%4Admin.evtx"
    )
    assert members[0]["stage"] == "started"


def test_p2_36_attack_completed_but_combined_revalidation_did_not() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = _row()
    run = row["execution"]
    summary = raw["attack_revalidation"]["summary"]
    assert summary == {
        "fixture_count": 7,
        "hits": 3,
        "misses": 4,
        "errors": 0,
        "fixture_hit_fraction": 3 / 7,
    }
    assert run["attack_phase_completed"] is True
    assert run["attack_fixture_count"] == 7
    assert run["attack_hits"] == 3
    assert run["attack_misses"] == 4
    assert run["attack_errors"] == 0
    assert run["benign_member_inventory_count"] == 355
    assert run["benign_attempted_member_count_before_failure"] == 1
    assert run["benign_completed_member_count_before_failure"] == 0
    assert run["benign_summary_completed"] is False

    claim = row["interpretation"]
    assert claim["attack_partial_result_is_fresh_attack_revalidation_claim"] is False
    assert claim["benign_fresh_revalidation_completed"] is False
    assert claim["combined_fresh_revalidation_completed"] is False
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36_analysis_id_is_permanently_retired() -> None:
    row = _row()
    assert row["execution"]["canonical_execution_started"] is True
    assert row["execution"]["same_analysis_id_retry_allowed"] is False
    assert row["execution"]["duplicate_execution_performed"] is False
    assert row["next_analysis"]["analysis_id"] == (
        "p2-36b-current-rulepack-fresh-source-revalidation-v1"
    )
    requirements = row["next_analysis"]["requirements"]
    assert any("do not reuse the P2-36 analysis id" in item for item in requirements)
    assert any("empty or zero-event EVTX" in item for item in requirements)
