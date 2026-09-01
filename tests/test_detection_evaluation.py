from __future__ import annotations

import importlib.util
import json

import yaml
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_detection_corpus.py"
MANIFEST = ROOT / "samples" / "evaluation" / "ground_truth.yaml"
BENIGN = ROOT / "samples" / "scenarios" / "benign_windows_processes.jsonl"


def _module():
    spec = importlib.util.spec_from_file_location(
        "breachscope_detection_evaluation",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_ground_truth_manifest_has_real_minimum_corpus_size():
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1"
    assert manifest["thresholds"]["min_malicious_events"] == 48
    assert manifest["thresholds"]["min_benign_events"] >= 20

    malicious = [
        x for x in manifest["corpora"]
        if x["classification"] == "malicious"
    ]
    benign = [
        x for x in manifest["corpora"]
        if x["classification"] == "benign"
    ]
    assert len(malicious) == 10
    assert len(benign) == 1


def test_benign_corpus_is_nontrivial_and_explicitly_labeled():
    rows = [
        json.loads(line)
        for line in BENIGN.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) >= 20
    assert all(row["evaluation_label"] == "benign" for row in rows)
    assert len({row["command_line"] for row in rows}) == len(rows)


def test_existing_scenario_corpus_exposes_expected_techniques():
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    malicious = [
        x for x in manifest["corpora"]
        if x["classification"] == "malicious"
    ]

    event_count = 0
    for entry in malicious:
        path = ROOT / entry["events_file"]
        rows = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        event_count += len(rows)
        field = entry["expected_techniques_field"]
        assert rows
        assert all(row.get(field) for row in rows)

    assert event_count == 48


def test_curated_detection_precision_recall_gate_passes():
    module = _module()
    result = module.evaluate(
        MANIFEST,
        rules_dir=ROOT / "rules",
    )

    assert result["passed"] is True
    assert result["counts"]["malicious_events"] == 48
    assert result["counts"]["benign_events"] >= 20
    assert result["metrics"]["precision"] >= 0.95
    assert result["metrics"]["recall"] >= 0.90
    assert result["counts"]["fp"] == 0


def test_metric_helper_is_fail_closed_for_zero_denominator():
    module = _module()
    assert module._metric(0, 0) == 1.0
    assert module._metric(3, 4) == 0.75


def test_evaluator_declares_curated_not_production_quality():
    module = _module()
    result = module.evaluate(
        MANIFEST,
        rules_dir=ROOT / "rules",
    )
    assert result["evaluation_kind"] == "curated_regression_corpus"
    assert any(
        "production" in item.lower()
        for item in result["limitations"]
    )
