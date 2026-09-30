from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FAILURE = (
    ROOT
    / "external_baseline"
    / "p2_36b_current_rulepack_fresh_source_revalidation_failure.yaml"
)
RAW = ROOT / "external_baseline" / "results" / "p2_36b_97f6fdd" / "result.json"
LOCK = (
    ROOT
    / "external_baseline"
    / "locks"
    / "P2_36B_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row() -> dict:
    return yaml.safe_load(FAILURE.read_text(encoding="utf-8"))


def test_p2_36b_failure_artifacts_are_exact() -> None:
    row = _row()
    assert row["status"] == "FAILED_CANONICAL_NO_RETRY"
    assert RAW.stat().st_size == 126_048
    assert LOCK.stat().st_size == 123
    assert _sha(RAW) == (
        "87f45b32f2b5242e6ee65ac9d21c774867a8e45ba30ae02d876bdc932d8eba3b"
    )
    assert _sha(LOCK) == (
        "f18900330f6e41684358ef591073f36a7bc8a0e2272fa47df652b5b6a0058142"
    )


def test_p2_36b_raw_result_stopped_mid_sysmon_member() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    row = _row()["execution"]
    assert raw["status"] == "sources_verified"
    assert "error" not in raw
    assert row["failure_class"] == "CANONICAL_EVALUATOR_PROCESS_LOST"
    assert row["failure_stage"] == "BENIGN_MEMBER_273_SYSMON_SCORING"
    assert row["root_cause"] == "NOT_ESTABLISHED"
    assert row["product_or_rules_failure"] is False
    assert row["source_identity_failure"] is False
    assert row["source_preflight_completed"] is True

    members = raw["benign_revalidation"]["members"]
    assert len(members) == 273
    assert members[-1] == {
        "name": "Logs_Win11/Microsoft-Windows-Sysmon%4Operational.evtx",
        "size_bytes": 1_743_781_888,
        "stage": "started",
    }
    assert "summary" not in raw["benign_revalidation"]


def test_p2_36b_attack_completed_as_single_fixture_miss() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    summary = raw["attack_revalidation"]["summary"]
    assert summary == {
        "fixture_count": 1,
        "hits": 0,
        "misses": 1,
        "errors": 0,
        "fixture_hit_fraction": 0.0,
    }
    dataset = raw["attack_revalidation"]["datasets"][0]
    assert dataset["fixture_status"] == "MISS"
    assert dataset["parsed_events"] == 2497
    assert dataset["findings"] == 0
    assert dataset["flagged_events"] == 0


def test_p2_36b_benign_partial_counts_match_raw_artifact() -> None:
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    members = raw["benign_revalidation"]["members"]
    done = [item for item in members if item.get("stage") == "completed"]
    empty = [item for item in done if item.get("member_status") == "EMPTY"]
    nonempty = [
        item for item in done if item.get("member_status") == "COMPLETED"
    ]

    row = _row()["benign_partial_execution"]
    assert len(done) == row["completed_member_count"] == 272
    assert len(empty) == row["empty_member_count"] == 196
    assert len(nonempty) == row["nonempty_completed_member_count"] == 76
    assert sum(int(item.get("raw_records", 0)) for item in done) == 23_554
    assert sum(int(item.get("parsed_events", 0)) for item in done) == 23_546
    assert sum(int(item.get("parse_errors", 0)) for item in done) == 8
    assert sum(int(item.get("findings", 0)) for item in done) == 0
    assert sum(int(item.get("flagged_events", 0)) for item in done) == 0
    assert row["benign_summary_completed"] is False


def test_p2_36b_partial_observations_do_not_become_performance_claims() -> None:
    claim = _row()["interpretation"]
    assert claim["attack_partial_result_is_fresh_attack_revalidation_claim"] is False
    assert claim["benign_partial_result_is_fresh_benign_revalidation_claim"] is False
    assert claim["combined_fresh_revalidation_completed"] is False
    assert claim["partial_zero_findings_is_confirmed_false_positive_rate"] is False
    assert claim["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"


def test_p2_36b_analysis_id_is_permanently_retired() -> None:
    row = _row()
    assert row["execution"]["canonical_execution_started"] is True
    assert row["execution"]["same_analysis_id_retry_allowed"] is False
    assert row["execution"]["duplicate_execution_performed"] is False
    assert row["next_analysis"]["analysis_id"] == (
        "p2-36c-current-rulepack-fresh-source-revalidation-v1"
    )
    requirements = row["next_analysis"]["requirements"]
    assert any("do not reuse the P2-36B analysis id" in item for item in requirements)
    assert any("bound the largest selected benign EVTX member" in item for item in requirements)


def test_p2_36b_exact_artifacts_are_marked_binary() -> None:
    attrs = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert (
        "external_baseline/locks/"
        "P2_36B_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock "
        "-text -whitespace"
    ) in attrs
    assert (
        "external_baseline/results/p2_36b_97f6fdd/result.json "
        "-text -eol -whitespace"
    ) in attrs
