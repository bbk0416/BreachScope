from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TAXONOMY = ROOT / "external_baseline" / "p2_11c_atomic_miss_taxonomy.json"


def _load() -> dict:
    return json.loads(TAXONOMY.read_text(encoding="utf-8"))


def test_p2_11c_taxonomy_binds_known_p2_11b_result() -> None:
    data = _load()
    assert data["analysis_class"] == "external_calibration"
    assert data["base_main_commit"] == "ff279db1593bee8fd6f4d247de3670e86eaa574b"
    assert data["source"]["p2_11b_result_sha256"] == (
        "89a309b8b59c5602afb4e3de1136fe53d9284463a8e409625f6a633629071a11"
    )
    assert data["claim_boundary"]["p2_11b_result"] == "0 HIT / 12 MISS"
    assert data["claim_boundary"]["future_runs_on_same_12_scenarios"] == "external_calibration"
    assert data["claim_boundary"]["final_blind_holdout"] is False


def test_p2_11c_probe_covers_all_scenarios_without_parse_errors() -> None:
    data = _load()
    assert data["probe"]["workflow_run_id"] == 34431613536
    assert data["probe"]["artifact_id"] == 10134693051
    assert data["probe"]["scenario_count"] == 12
    assert data["probe"]["event_count"] == 902
    assert data["probe"]["parse_errors"] == 0
    scenarios = data["scenarios"]
    assert len(scenarios) == 12
    assert len({item["scenario_id"] for item in scenarios}) == 12
    assert sum(item["events"] for item in scenarios) == 902
    assert all(item["parse_errors"] == 0 for item in scenarios)


def test_p2_11c_highest_priority_is_tool_independent_4720() -> None:
    data = _load()
    first = data["recommended_order"][0]
    assert first["candidate"] == "Security 4720 -> T1136.001"
    assert set(first["covers"]) == {"T1136.001-4", "T1136.001-5"}
    assert first["status"] == "BENIGN_CHECK_FIRST"

    by_id = {item["scenario_id"]: item for item in data["scenarios"]}
    assert by_id["T1136.001-4"]["classification"] == "direct_event_rule_gap"
    assert by_id["T1136.001-5"]["classification"] == "direct_event_rule_gap"
    assert by_id["T1003-1"]["calibration_priority"] == "hold"
    assert by_id["T1003-2"]["calibration_priority"] == "hold"
    assert by_id["T1021.001-2"]["calibration_priority"] == "hold"
