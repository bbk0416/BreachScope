from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_reproducible_benchmark.py"
MANIFEST = ROOT / "external_baseline" / "p2_09e_benchmark.yaml"


def test_recorded_benchmark_verifies_without_network() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout)

    assert data["status"] == "PASS"
    assert data["rules_tree_sha256"] == (
        "543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce"
    )
    assert data["attack"]["scenario_hits"] == 2
    assert data["attack"]["scenario_total"] == 10
    assert data["benign"]["events"] == 766623
    assert data["benign"]["false_positives"] == 17
    assert data["benign"]["true_negatives"] == 766606
    assert len(data["evidence_bundle_sha256"]) == 64


def test_benchmark_claim_boundaries_are_explicit() -> None:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    assert data["benchmark_type"] == "detection_evidence_not_performance"
    assert data["claim_boundary"]["production_accuracy"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["production_false_positive_rate"] == "NOT_CLAIMED"
    assert data["claim_boundary"]["final_blind_holdout"] is False
    assert data["claim_boundary"]["performance_benchmark"] == "NOT_CLAIMED"
    assert data["reproducibility"]["network_required_for_recorded_evidence_verification"] is False


def test_benchmark_keeps_attack_and_benign_rule_hash_equal() -> None:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    common = data["common_detection_contract"]["rules_tree_sha256"]
    components = data["components"]

    assert components["attack_external_baseline"]["rules_tree_sha256"] == common
    assert components["benign_external_baseline"]["rules_tree_sha256"] == common
    assert data["common_detection_contract"]["commit_range_detection_semantics_changed"] is False
