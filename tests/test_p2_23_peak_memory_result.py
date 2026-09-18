from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "performance" / "p2_23_peak_memory_result.yaml"
FAILURE = ROOT / "performance" / "results" / "p2_23_203fca3" / "precondition_failure.json"


def _load() -> dict:
    return yaml.safe_load(RESULT.read_text(encoding="utf-8-sig"))


def test_p2_23_retains_python_precondition_failure() -> None:
    row = _load()
    assert row["status"] == "FAILED_PRECONDITION"
    assert row["failure"]["stage"] == "launcher_precondition"
    assert row["failure"]["required_python_major_minor"] == "3.11"
    assert row["failure"]["observed_python_version"] == "3.13.15"
    assert row["failure"]["exit_code"] == 1


def test_p2_23_measured_nothing_before_failure() -> None:
    row = _load()
    execution = row["benchmark_execution"]
    assert execution["orchestrate_entered"] is False
    assert execution["permanent_lock_created"] is False
    assert execution["source_generated"] is False
    assert execution["worker_process_started"] is False
    assert execution["measurement_rows"] == 0
    assert execution["scales_measured"] == []
    assert row["claim_boundary"]["peak_working_set_mb"] == "NOT_MEASURED"
    assert row["claim_boundary"]["formal_1m_result"] == "NOT_MEASURED"


def test_p2_23_failure_artifact_matches_record() -> None:
    row = _load()
    payload = json.loads(FAILURE.read_text(encoding="utf-8"))
    assert payload["attempt"]["status"] == "PRECONDITION_FAILED_BEFORE_BENCHMARK_START"
    assert payload["execution_state"]["measurement_rows"] == 0
    assert payload["canonical_interpretation"]["same_benchmark_id_rerun_allowed"] is False
    assert row["artifact"]["sha256"] == hashlib.sha256(FAILURE.read_bytes()).hexdigest()


def test_p2_23_requires_new_benchmark_id_after_failure() -> None:
    protocol = _load()["protocol_interpretation"]
    assert protocol["first_attempt_retained"] is True
    assert protocol["same_benchmark_id_rerun_allowed"] is False
    assert protocol["replacement_result_for_better_numbers_allowed"] is False
    assert protocol["new_benchmark_id_required_for_next_measurement"] is True
