from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_SCRIPT = ROOT / "scripts" / "verify_reproducible_benchmark.py"
CURRENT_SCRIPT = ROOT / "scripts" / "verify_current_detection_evidence.py"
CURRENT_CHAIN = ROOT / "external_baseline" / "current_detection_evidence.yaml"
_HISTORICAL_TESTS = ROOT / "tests" / "_reproducible_benchmark_p2_11h.py"

_spec = importlib.util.spec_from_file_location("_p2_11h_reproducible_tests", _HISTORICAL_TESTS)
assert _spec is not None and _spec.loader is not None
_hist = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hist)

_OVERRIDES = {
    "test_historical_p2_09e_verifier_fails_closed_after_rule_drift",
    "test_current_detection_evidence_chain_verifies_without_network",
    "test_current_chain_keeps_claim_boundaries_explicit",
}
for _name in dir(_hist):
    if not _name.startswith("test_") or _name in _OVERRIDES:
        continue
    _fn = getattr(_hist, _name)
    if not callable(_fn):
        continue

    def _wrapper(_fn=_fn):
        return _fn()

    _wrapper.__name__ = _name
    _wrapper.__qualname__ = _name
    globals()[_name] = _wrapper


def test_historical_p2_09e_verifier_fails_closed_after_rule_drift() -> None:
    proc = subprocess.run(
        [sys.executable, str(HISTORICAL_SCRIPT), "--json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "current rule tree hash" in proc.stdout
    assert "543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce" in proc.stdout
    assert "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92" in proc.stdout


def test_current_detection_evidence_chain_verifies_without_network() -> None:
    proc = subprocess.run(
        [sys.executable, str(CURRENT_SCRIPT), "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)

    assert data["status"] == "PASS"
    assert data["schema"] == "breachscope.current_detection_evidence_verification.v5"
    assert data["current_evidence_id"] == "p2-11j-current-detection-evidence"
    assert data["current_rules_tree_sha256"] == "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
    assert data["rule_file_count"] == 4
    assert data["base_attack_scenario_hits"] == 2
    assert data["current_attack_scenario_hits"] == 10
    assert data["attack_scenario_total"] == 10
    assert data["historical_benign"]["events"] == 766623
    assert len(data["calibrations"]) == 6
    j = data["calibrations"][-1]
    assert j["calibration_id"] == "p2-11j-t1003-networkprovider-credential-capture"
    assert j["from_rules_tree_sha256"] == "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
    assert j["to_rules_tree_sha256"] == data["current_rules_tree_sha256"]
    assert j["scenario_hits_before"] == 8
    assert j["scenario_hits_after"] == 9
    assert j["scenario_total"] == 12
    assert j["events"] == 902
    assert j["rules"] == 66
    assert j["findings"] == 92
    assert j["flagged_events"] == 88
    assert j["benign_events_scanned"] == 732200
    assert j["benign_exact_predicate_matches"] == 0
    assert j["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"


def test_current_chain_keeps_claim_boundaries_explicit() -> None:
    data = yaml.safe_load(CURRENT_CHAIN.read_text(encoding="utf-8"))
    assert data["schema"] == "breachscope.current_detection_evidence_chain.v1"
    assert data["current_evidence_id"] == "p2-11j-current-detection-evidence"
    assert [row["calibration_id"] for row in data["calibrations"]] == [
        "p2-11d-local-account-4720",
        "p2-11e-t1007-service-discovery",
        "p2-11f-t1006-direct-volume-access",
        "p2-11g-t1027-encoded-powershell-mapping",
        "p2-11h-t1047-wmic-query",
        "p2-11j-t1003-networkprovider-credential-capture",
    ]
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
