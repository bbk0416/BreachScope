from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path

REPO = Path(r"C:\Users\bbk0416\Projects\BreachScope-p2-17b-run")
DATA = Path(r"C:\Users\bbk0416\Projects\BreachScope-p2-17b-data")
OUT = Path(r"C:\Users\bbk0416\Projects\p2_17b_one_pass_result.json")
FROZEN = "34e4d4440f57d4c8a83f77da60807458a71816c8"
RULES_SHA = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"

DATASETS = [
    ("T1059.001", "T1059.001.log", "8f71b2a0ef81892551cd6a9ad115b8ec5c42d9f2071547b064c496511898c4e9", 38928903),
    ("T1543.003", "T1543.003.log", "2e6ea9e053a84f4d32b37f462a40a39f1a90c2049adaf684b0660ee6e9f32d7a", 11281916),
    ("T1053.005", "T1053.005.log", "d346ab6c75b3151217dfc2c4c166c951fc16d68c31b7d5a8f3e577d9545ff9f0", 11410982),
    ("T1047", "T1047.log", "64651720e10813aa57d0f25ce149005ab06039b1974dbc09818b1fb45fbbc196", 11815541),
    ("T1218.011", "T1218.011.log", "0805f7d8a89371dee4f75c001ef11574c2d759d91626c1625bca7c9174cfe29f", 23784139),
]

sys.path.insert(0, str(REPO))

from breachscope.analyzer import apply_rules
from breachscope.correlator import correlate_events
from breachscope.ingest import _extract_from_xml
from breachscope.rules import load_rules
from breachscope.scenario import infer_scenarios
from breachscope.utils import get_event_identity_key
from scripts.evaluate_external_holdout import (
    _finding_techniques,
    _record_to_event,
    rules_tree_hash,
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head() -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
    ).strip()
def verify_inputs() -> dict:
    head = git_head()
    if head != FROZEN:
        raise RuntimeError(f"frozen commit mismatch: {head} != {FROZEN}")
    rules_hash, rule_files = rules_tree_hash(REPO / "rules")
    if rules_hash != RULES_SHA:
        raise RuntimeError(f"rules hash mismatch: {rules_hash}")
    checked = []
    for technique, name, expected_sha, expected_size in DATASETS:
        path = DATA / name
        size = path.stat().st_size
        digest = sha256(path)
        if size != expected_size or digest != expected_sha:
            raise RuntimeError(f"source mismatch: {technique}")
        checked.append({
            "technique_id": technique,
            "file": name,
            "size_bytes": size,
            "sha256": digest,
        })
    return {
        "repo_commit": head,
        "rules_tree_sha256": rules_hash,
        "rule_file_count": rule_files,
        "sources": checked,
    }


def load_xml_events(path: Path):
    events = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                raw = _extract_from_xml(line)
                if not isinstance(raw, dict) or not raw:
                    raise ValueError("empty parser result")
                events.append(_record_to_event(raw))
            except Exception:
                parse_errors += 1
    return events, parse_errors
def evaluate_dataset(technique: str, path: Path, rules) -> dict:
    tracemalloc.start()
    started = time.perf_counter()
    events, parse_errors = load_xml_events(path)
    load_s = time.perf_counter() - started

    started = time.perf_counter()
    findings = list(apply_rules(events, rules))
    detection_s = time.perf_counter() - started
    flagged = {get_event_identity_key(f.event) for f in findings}
    observed = sorted({
        value
        for finding in findings
        for value in _finding_techniques(finding)
    })

    started = time.perf_counter()
    chains = correlate_events(events, findings)
    correlation_s = time.perf_counter() - started
    chain_types = Counter(chain.chain_type for chain in chains)

    started = time.perf_counter()
    scenarios = infer_scenarios(chains, findings)
    scenario_s = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "expected_technique": technique,
        "status": "completed",
        "events": len(events),
        "parse_errors": parse_errors,
        "findings": len(findings),
        "flagged_events": len(flagged),
        "observed_finding_technique_ids": observed,
        "expected_technique_hit": technique in observed,
        "chains": len(chains),
        "chain_types": dict(sorted(chain_types.items())),
        "scenarios": len(scenarios),
        "timing_seconds": {
            "load": round(load_s, 6),
            "detection": round(detection_s, 6),
            "correlation": round(correlation_s, 6),
            "scenario": round(scenario_s, 6),
        },
        "peak_python_bytes": peak,
    }


def write_result(result: dict) -> None:
    tmp = OUT.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, OUT)


def main() -> int:
    if OUT.exists():
        raise RuntimeError(f"one-pass output already exists: {OUT}")
    frozen = verify_inputs()
    rules = load_rules(REPO / "rules")
    result = {
        "schema": "breachscope.p2_17b_attack_data_one_pass.v1",
        "analysis_class": "independent_external_path_labeled_holdout_one_pass",
        "status": "in_progress",
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
        },
        "frozen": frozen,
        "datasets": [],
        "claim_boundary": {
            "event_level_ground_truth": "NOT_AVAILABLE",
            "detection_precision": "NOT_CLAIMED",
            "detection_recall": "NOT_CLAIMED",
            "false_positive_rate": "NOT_CLAIMED",
            "path_label_dataset_hit_rate": "MEASURABLE",
            "chain_precision": "NOT_CLAIMED",
            "chain_recall": "NOT_CLAIMED",
            "scenario_accuracy": "NOT_CLAIMED",
            "production_quality": "NOT_CLAIMED",
        },
    }
    write_result(result)

    for technique, name, _, _ in DATASETS:
        row = evaluate_dataset(technique, DATA / name, rules)
        result["datasets"].append(row)
        write_result(result)
        print(
            technique,
            "HIT" if row["expected_technique_hit"] else "MISS",
            "events", row["events"],
            "findings", row["findings"],
            flush=True,
        )

    hits = sum(row["expected_technique_hit"] for row in result["datasets"])
    result["status"] = "completed"
    result["summary"] = {
        "dataset_count": len(result["datasets"]),
        "hits": hits,
        "misses": len(result["datasets"]) - hits,
        "path_label_dataset_hit_rate": hits / len(result["datasets"]),
        "total_events": sum(row["events"] for row in result["datasets"]),
        "total_parse_errors": sum(row["parse_errors"] for row in result["datasets"]),
        "total_findings": sum(row["findings"] for row in result["datasets"]),
        "total_flagged_events": sum(row["flagged_events"] for row in result["datasets"]),
    }
    write_result(result)
    print(json.dumps(result["summary"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
