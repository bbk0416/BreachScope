from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_11j_357b7ea8"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_p2_11j_artifact_bytes_are_locked() -> None:
    assert _sha256(RESULT_DIR / "aggregate-result.json") == "82cd205ac90b17d72a947448418d17382926967c1cf801a0882745900c03a0f7"
    assert _sha256(RESULT_DIR / "rules-freeze.json") == "9975bdbc0efcf31d7a7a92c7cb28f4e9186704f0660282abc603c61d10cee5fc"
    assert _sha256(RESULT_DIR / "benign-probe.json") == "4942c9782ade6c2dc1148a214efc54db4579ba219d3196dfa52bf1a6b08f8b65"


def test_p2_11j_measurement_records_only_supported_claims() -> None:
    measurement = yaml.safe_load((RESULT_DIR / "measurement.yaml").read_text(encoding="utf-8"))
    aggregate = json.loads((RESULT_DIR / "aggregate-result.json").read_text(encoding="utf-8"))
    benign = json.loads((RESULT_DIR / "benign-probe.json").read_text(encoding="utf-8"))

    assert measurement["measurement_class"] == "external_calibration"
    assert measurement["external_calibration"]["before_scenario_hits"] == 8
    assert measurement["external_calibration"]["after_scenario_hits"] == 9
    assert measurement["external_calibration"]["changed_scenarios"] == ["T1003-2"]
    assert measurement["external_calibration"]["remaining_miss_scenarios"] == [
        "T1003-1",
        "T1021.001-1",
        "T1021.001-2",
    ]
    assert aggregate["scenario_hits"] == 9
    assert aggregate["scenario_misses"] == 3
    assert aggregate["events"] == 902
    assert aggregate["rules"] == 66
    assert aggregate["findings"] == 92
    assert aggregate["flagged_events"] == 88
    outcomes = {row["scenario_id"]: row["status"] for row in aggregate["outcomes"]}
    assert outcomes["T1003-2"] == "hit"

    assert benign["scope"]["sysmon_records"] == 732200
    assert benign["scope"]["sysmon_event1"] == 2149
    assert benign["scope"]["parse_errors"] == 0
    assert set(benign["candidate_counts"].values()) == {0}

    claims = measurement["claim_boundary"]
    assert claims["final_blind_holdout"] is False
    assert claims["fresh_external_baseline"] is False
    assert claims["production_detection_rate"] == "NOT_CLAIMED"
    assert claims["production_precision"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"
