#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

FROZEN_DETECTOR_COMMIT = "674615ef3c92d5b4bbc4dec71f566d49de0454f4"
FROZEN_RULE_TREE = "371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f"
FROZEN_ANALYZER_BLOB = "f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7"
FROZEN_P2_10_RULE_BLOB = "3a2f853fd6c8232f7d919913fd711d7f18785108"
FROZEN_SELECTION_COMMIT = "7541214400507afddca40a22f2adb22504fc3946"
FROZEN_SCORE_PLAN_COMMIT = "cb86f4b5dbde0c517c395217e2fcf2a9a213a6cf"
SOURCE_COMMIT = "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
SELECTION_PATH = "external_baseline/p2_11b_atomic_evtx_selection.yaml"
BINDING_PATH = "external_baseline/p2_11b_atomic_evtx_byte_binding.json"
PLAN_PATH = "external_baseline/p2_11b_atomic_evtx_score_plan.yaml"
EXPECTED_ORDER = [
    "T1003-1", "T1003-2", "T1006-1", "T1027-2", "T1007-1", "T1007-2",
    "T1021.001-1", "T1021.001-2", "T1047-1", "T1047-2", "T1136.001-4", "T1136.001-5",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    header = f"blob {len(data)}".encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def run(*args: str, cwd: Path | None = None) -> None:
    print("[run]", " ".join(args), flush=True)
    subprocess.run(list(args), cwd=cwd, check=True)


def frozen_selection(control: Path) -> dict:
    text = subprocess.check_output(
        ["git", "show", f"{FROZEN_SELECTION_COMMIT}:{SELECTION_PATH}"], cwd=control, text=True
    )
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise RuntimeError("frozen selection must be a mapping")
    return data


def verify_control(control: Path) -> tuple[dict, dict, dict]:
    if not git(control, "merge-base", "--is-ancestor", FROZEN_SCORE_PLAN_COMMIT, "HEAD") == "":
        pass
    current_plan = (control / PLAN_PATH).read_bytes()
    frozen_plan = subprocess.check_output(
        ["git", "show", f"{FROZEN_SCORE_PLAN_COMMIT}:{PLAN_PATH}"], cwd=control
    )
    if current_plan != frozen_plan:
        raise RuntimeError("score plan changed after frozen plan commit")

    selection = frozen_selection(control)
    binding = json.loads((control / BINDING_PATH).read_text(encoding="utf-8"))
    plan = yaml.safe_load((control / PLAN_PATH).read_text(encoding="utf-8"))
    if not isinstance(plan, dict):
        raise RuntimeError("score plan must be a mapping")

    scenario_ids = [str(x["scenario_id"]) for x in selection["scenarios"]]
    if scenario_ids != EXPECTED_ORDER:
        raise RuntimeError(f"frozen selection order mismatch: {scenario_ids!r}")
    if binding.get("selection_commit") != FROZEN_SELECTION_COMMIT:
        raise RuntimeError("byte binding does not reference frozen selection")
    if binding.get("source_commit") != SOURCE_COMMIT:
        raise RuntimeError("byte binding source commit mismatch")
    if [x["scenario_id"] for x in binding["scenarios"]] != EXPECTED_ORDER:
        raise RuntimeError("byte binding scenario order mismatch")
    if int(binding.get("scenario_count", -1)) != 12 or int(binding.get("evtx_file_count", -1)) != 60:
        raise RuntimeError("byte binding count mismatch")
    if binding.get("detection_executed") is not False:
        raise RuntimeError("byte binding must predate detection")
    if plan["scoring_protocol"]["score_order"] != EXPECTED_ORDER:
        raise RuntimeError("score plan order mismatch")
    if plan["protocol_attestations"]["detection_executed_before_this_plan"] is not False:
        raise RuntimeError("score plan does not attest pre-detection state")
    return selection, binding, plan


def verify_detector(detector: Path) -> None:
    if git(detector, "rev-parse", "HEAD") != FROZEN_DETECTOR_COMMIT:
        raise RuntimeError("detector commit mismatch")
    if git(detector, "status", "--porcelain", "-uall"):
        raise RuntimeError("detector working tree is not clean")
    if git_blob_sha1(detector / "breachscope/analyzer.py") != FROZEN_ANALYZER_BLOB:
        raise RuntimeError("analyzer blob mismatch")
    if git_blob_sha1(detector / "rules/p2_10_event_rules.yml") != FROZEN_P2_10_RULE_BLOB:
        raise RuntimeError("P2-10 rule blob mismatch")


def verify_source(source: Path, binding: dict) -> dict[str, dict]:
    if git(source, "rev-parse", "HEAD") != SOURCE_COMMIT:
        raise RuntimeError("external source commit mismatch")
    manifest = source / "full_list_of_attacks_simulated.csv"
    if sha256(manifest) != binding["source_manifest_sha256"]:
        raise RuntimeError("external source manifest SHA-256 mismatch")
    rows = {}
    for scenario in binding["scenarios"]:
        scenario_id = scenario["scenario_id"]
        for item in scenario["evtx_files"]:
            path = source / item["path"]
            if not path.is_file():
                raise RuntimeError(f"missing bound EVTX: {item['path']}")
            if path.stat().st_size != int(item["bytes"]):
                raise RuntimeError(f"bound EVTX size mismatch: {item['path']}")
            if sha256(path) != item["sha256"]:
                raise RuntimeError(f"bound EVTX SHA-256 mismatch: {item['path']}")
        rows[scenario_id] = scenario
    return rows


def make_labels(index_path: Path, labels_path: Path) -> str:
    count = 0
    with index_path.open("r", encoding="utf-8") as src, labels_path.open("w", encoding="utf-8", newline="\n") as dst:
        for line in src:
            if not line.strip():
                continue
            row = json.loads(line)
            dst.write(json.dumps({
                "event_key": row["event_key"],
                "label": "ignore",
                "expected_techniques": [],
                "notes": "Scenario-only external baseline; no independent event-level ground truth.",
            }, ensure_ascii=False) + "\n")
            count += 1
    if count <= 0:
        raise RuntimeError("index produced zero events")
    return sha256(labels_path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--control-root", required=True)
    ap.add_argument("--detector-root", required=True)
    ap.add_argument("--source-root", required=True)
    ap.add_argument("--out-root", required=True)
    args = ap.parse_args()

    control = Path(args.control_root).resolve()
    detector = Path(args.detector_root).resolve()
    source = Path(args.source_root).resolve()
    out = Path(args.out_root).resolve()
    out.mkdir(parents=True, exist_ok=True)

    selection, binding, plan = verify_control(control)
    verify_detector(detector)
    bound_by_id = verify_source(source, binding)

    evaluator = detector / "scripts/evaluate_external_holdout.py"
    freeze = out / "rules-freeze.json"
    run(sys.executable, str(evaluator), "freeze", "--repo", str(detector), "--rules-dir", str(detector / "rules"), "--out", str(freeze), cwd=detector)
    freeze_data = json.loads(freeze.read_text(encoding="utf-8"))
    if freeze_data["repo_commit"] != FROZEN_DETECTOR_COMMIT or freeze_data["rules_tree_sha256"] != FROZEN_RULE_TREE:
        raise RuntimeError("runtime freeze differs from P2-11A frozen detector")

    selected = {str(x["scenario_id"]): x for x in selection["scenarios"]}
    prepared: list[dict] = []
    acquired_at = datetime.now(timezone.utc).isoformat()

    # Phase 1: verify corpus, index WITHOUT detection, bind all-ignore event labels.
    for scenario_id in EXPECTED_ORDER:
        scenario = selected[scenario_id]
        bound = bound_by_id[scenario_id]
        scenario_dir = source / "ttp_evtx" / scenario_id
        case_dir = out / "scenarios" / scenario_id
        case_dir.mkdir(parents=True, exist_ok=True)
        files = []
        source_files = []
        for item in bound["evtx_files"]:
            name = Path(item["path"]).name
            files.append({"path": name, "sha256": item["sha256"], "format": "evtx"})
            source_files.append(name)
        manifest_data = {
            "schema": "breachscope.external_holdout.v1",
            "kind": "external_blind_holdout",
            "evaluation_class": "external_baseline",
            "protocol": {
                "independent_from_rule_authoring": False,
                "ground_truth_prepared_without_breachscope_findings": True,
                "final_holdout_seen_before_rule_freeze": False,
            },
            "provenance": {
                "source": f"arniki/atomic-evtx@{SOURCE_COMMIT}:{scenario['source_directory']}",
                "acquired_at": acquired_at,
                "license_or_permission": "Public GitHub repository; repository metadata reports no license. Source EVTX bytes are used transiently for evaluation and are not redistributed in BreachScope artifacts.",
                "notes": "Selected after P2-11A freeze by the precommitted P2-11B policy; Atomic Red Team framework family is not independent from all prior public attack provenance.",
            },
            "files": files,
            "scenarios": [{
                "scenario_id": scenario_id,
                "source_files": source_files,
                "expected_techniques": [str(scenario["expected_technique"]).upper()],
            }],
        }
        manifest_path = case_dir / "manifest.yaml"
        manifest_path.write_text(yaml.safe_dump(manifest_data, sort_keys=False, allow_unicode=True), encoding="utf-8", newline="\n")
        index_path = case_dir / "event-index.jsonl"
        run(sys.executable, str(evaluator), "index", "--manifest", str(manifest_path), "--corpus-root", str(scenario_dir), "--out", str(index_path), cwd=detector)
        labels_path = case_dir / "labels.jsonl"
        labels_hash = make_labels(index_path, labels_path)
        manifest_data["labels"] = {"sha256": labels_hash}
        manifest_path.write_text(yaml.safe_dump(manifest_data, sort_keys=False, allow_unicode=True), encoding="utf-8", newline="\n")
        prepared.append({
            "scenario_id": scenario_id,
            "scenario_dir": scenario_dir,
            "case_dir": case_dir,
            "manifest": manifest_path,
            "labels": labels_path,
        })

    # Phase 2: only after every selected scenario is indexed and label-hash bound, execute detection once per scenario.
    outcomes = []
    rule_counts = set()
    totals = {"events": 0, "findings": 0, "flagged_events": 0, "flagged_ignored_events": 0}
    runtime_sum = 0.0
    peak_memory_max = 0.0
    for item in prepared:
        result_path = item["case_dir"] / "result.json"
        run(
            sys.executable, str(evaluator), "score",
            "--repo", str(detector),
            "--manifest", str(item["manifest"]),
            "--corpus-root", str(item["scenario_dir"]),
            "--labels", str(item["labels"]),
            "--freeze", str(freeze),
            "--rules-dir", str(detector / "rules"),
            "--out", str(result_path),
            cwd=detector,
        )
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("schema") != "breachscope.external_holdout.result.v1":
            raise RuntimeError("unexpected evaluator result schema")
        if result["claim_boundary"]["evaluation_class"] != "external_baseline":
            raise RuntimeError("unexpected evaluation class")
        if result["corpus"]["scored_events"] != 0 or result["corpus"]["ignored_events"] != result["corpus"]["events"]:
            raise RuntimeError("event labels were not all ignore")
        if result["scenarios"]["total"] != 1:
            raise RuntimeError("per-scenario score must contain exactly one scenario")
        outcome = result["scenarios"]["outcomes"][0]
        if outcome["scenario_id"] != item["scenario_id"]:
            raise RuntimeError("scenario result id mismatch")
        rule_counts.add(int(result["detection"]["rules"]))
        totals["events"] += int(result["corpus"]["events"])
        totals["findings"] += int(result["detection"]["findings"])
        totals["flagged_events"] += int(result["detection"]["flagged_events"])
        totals["flagged_ignored_events"] += int(result["detection"]["flagged_ignored_events"])
        runtime_sum += float(result["performance"]["runtime_seconds"])
        peak_memory_max = max(peak_memory_max, float(result["performance"]["peak_memory_mb"]))
        outcomes.append({
            **outcome,
            "manifest_sha256": result["corpus"]["manifest_sha256"],
            "labels_sha256": result["corpus"]["labels_sha256"],
            "findings": result["detection"]["findings"],
            "flagged_events": result["detection"]["flagged_events"],
        })

    if rule_counts != {60}:
        raise RuntimeError(f"unexpected rule counts: {sorted(rule_counts)}")
    hits = sum(x["status"] == "hit" for x in outcomes)
    misses = len(outcomes) - hits
    aggregate = {
        "schema": "breachscope.p2_11b_external_baseline_result.v1",
        "evaluation_class": "external_baseline",
        "score_plan_frozen_commit": FROZEN_SCORE_PLAN_COMMIT,
        "selection_frozen_commit": FROZEN_SELECTION_COMMIT,
        "detector_repo_commit": FROZEN_DETECTOR_COMMIT,
        "rules_tree_sha256": FROZEN_RULE_TREE,
        "source_repository": "arniki/atomic-evtx",
        "source_commit": SOURCE_COMMIT,
        "scenario_total": len(outcomes),
        "scenario_hits": hits,
        "scenario_misses": misses,
        "scenario_hit_rate": hits / len(outcomes),
        "rules": 60,
        **totals,
        "runtime_seconds_sum": runtime_sum,
        "peak_memory_mb_max": peak_memory_max,
        "event_level": {
            "labels": "all_ignore",
            "precision": "NOT_CLAIMED",
            "recall": "NOT_CLAIMED",
            "false_positive_rate": "NOT_CLAIMED",
        },
        "claim_boundary": {
            "final_blind_holdout": False,
            "production_detection_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "note": "Known public Atomic Red Team corpus scored as an external_baseline after precommitted selection, byte binding, scenario labels, and scoring protocol. Event-level labels were all ignore.",
        },
        "outcomes": outcomes,
    }
    aggregate_path = out / "aggregate-result.json"
    aggregate_path.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    verify_detector(detector)
    print(json.dumps({
        "scenario_total": aggregate["scenario_total"],
        "scenario_hits": aggregate["scenario_hits"],
        "scenario_misses": aggregate["scenario_misses"],
        "events": aggregate["events"],
        "findings": aggregate["findings"],
        "flagged_events": aggregate["flagged_events"],
        "rules": aggregate["rules"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
