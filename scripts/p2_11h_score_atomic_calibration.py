#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

DETECTOR_COMMIT = "7f46b3a29306328716dc02c176b4501eb2ef261b"
EXPECTED_RULE_TREE = "c8b35af39d19f569c0a54c723dfdda35d61a966f54016cd8568b19cdecb4b2ec"
EXPECTED_RULE_COUNT = 65
SOURCE_COMMIT = "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
FROZEN_SELECTION_COMMIT = "7541214400507afddca40a22f2adb22504fc3946"
SELECTION_PATH = "external_baseline/p2_11b_atomic_evtx_selection.yaml"
BINDING_PATH = "external_baseline/p2_11b_atomic_evtx_byte_binding.json"
EXPECTED_ORDER = [
    "T1003-1", "T1003-2", "T1006-1", "T1027-2", "T1007-1", "T1007-2",
    "T1021.001-1", "T1021.001-2", "T1047-1", "T1047-2", "T1136.001-4", "T1136.001-5",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def run(*args: str, cwd: Path | None = None) -> None:
    print("[run]", " ".join(args), flush=True)
    subprocess.run(list(args), cwd=cwd, check=True)


def verify_inputs(control: Path, detector: Path, source: Path) -> tuple[dict, dict]:
    if git(detector, "rev-parse", "HEAD") != DETECTOR_COMMIT:
        raise RuntimeError("detector commit mismatch")
    if git(detector, "status", "--porcelain", "-uall"):
        raise RuntimeError("detector working tree is not clean")
    if git(source, "rev-parse", "HEAD") != SOURCE_COMMIT:
        raise RuntimeError("source commit mismatch")

    selection = yaml.safe_load((control / SELECTION_PATH).read_text(encoding="utf-8"))
    binding = json.loads((control / BINDING_PATH).read_text(encoding="utf-8"))
    if not isinstance(selection, dict) or not isinstance(binding, dict):
        raise RuntimeError("selection/binding format invalid")

    scenario_ids = [str(row["scenario_id"]) for row in selection["scenarios"]]
    if scenario_ids != EXPECTED_ORDER:
        raise RuntimeError(f"selection order mismatch: {scenario_ids!r}")
    if binding.get("selection_commit") != FROZEN_SELECTION_COMMIT:
        raise RuntimeError("binding selection commit mismatch")
    if binding.get("source_commit") != SOURCE_COMMIT:
        raise RuntimeError("binding source commit mismatch")
    if [str(row["scenario_id"]) for row in binding["scenarios"]] != EXPECTED_ORDER:
        raise RuntimeError("binding scenario order mismatch")
    if int(binding.get("scenario_count", -1)) != 12:
        raise RuntimeError("binding scenario count mismatch")
    if int(binding.get("evtx_file_count", -1)) != 60:
        raise RuntimeError("binding EVTX count mismatch")
    if binding.get("detection_executed") is not False:
        raise RuntimeError("binding must predate detection")

    source_manifest = source / "full_list_of_attacks_simulated.csv"
    if sha256(source_manifest) != str(binding["source_manifest_sha256"]):
        raise RuntimeError("source manifest SHA-256 mismatch")
    for scenario in binding["scenarios"]:
        for item in scenario["evtx_files"]:
            path = source / str(item["path"])
            if not path.is_file():
                raise RuntimeError(f"missing bound EVTX: {item['path']}")
            if path.stat().st_size != int(item["bytes"]):
                raise RuntimeError(f"bound EVTX size mismatch: {item['path']}")
            if sha256(path) != str(item["sha256"]):
                raise RuntimeError(f"bound EVTX SHA-256 mismatch: {item['path']}")
    return selection, binding


def make_labels(index_path: Path, labels_path: Path) -> str:
    count = 0
    with index_path.open("r", encoding="utf-8") as src, labels_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as dst:
        for line in src:
            if not line.strip():
                continue
            row = json.loads(line)
            dst.write(json.dumps({
                "event_key": row["event_key"],
                "label": "ignore",
                "expected_techniques": [],
                "notes": "P2-11H external calibration; no independent event-level ground truth.",
            }, ensure_ascii=False) + "\n")
            count += 1
    if count <= 0:
        raise RuntimeError("index produced zero events")
    return sha256(labels_path)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--control-root", required=True)
    p.add_argument("--detector-root", required=True)
    p.add_argument("--source-root", required=True)
    p.add_argument("--out-root", required=True)
    args = p.parse_args()

    control = Path(args.control_root).resolve()
    detector = Path(args.detector_root).resolve()
    source = Path(args.source_root).resolve()
    out = Path(args.out_root).resolve()
    out.mkdir(parents=True, exist_ok=True)

    selection, binding = verify_inputs(control, detector, source)
    selected = {str(row["scenario_id"]): row for row in selection["scenarios"]}
    bound = {str(row["scenario_id"]): row for row in binding["scenarios"]}
    evaluator = detector / "scripts/evaluate_external_holdout.py"

    freeze = out / "rules-freeze.json"
    run(sys.executable, str(evaluator), "freeze", "--repo", str(detector),
        "--rules-dir", str(detector / "rules"), "--out", str(freeze), cwd=detector)
    freeze_data = json.loads(freeze.read_text(encoding="utf-8"))
    if freeze_data["repo_commit"] != DETECTOR_COMMIT:
        raise RuntimeError("runtime freeze detector commit mismatch")
    if freeze_data["rules_tree_sha256"] != EXPECTED_RULE_TREE:
        raise RuntimeError(f"runtime rules hash mismatch: {freeze_data['rules_tree_sha256']}")
    if int(freeze_data["rule_file_count"]) != 4:
        raise RuntimeError("runtime rule file count mismatch")

    acquired_at = datetime.now(timezone.utc).isoformat()
    prepared: list[dict] = []
    for scenario_id in EXPECTED_ORDER:
        scenario = selected[scenario_id]
        binding_row = bound[scenario_id]
        scenario_dir = source / "ttp_evtx" / scenario_id
        case_dir = out / "scenarios" / scenario_id
        case_dir.mkdir(parents=True, exist_ok=True)

        files = []
        source_files = []
        for item in binding_row["evtx_files"]:
            name = Path(str(item["path"])).name
            files.append({"path": name, "sha256": item["sha256"], "format": "evtx"})
            source_files.append(name)

        manifest = {
            "schema": "breachscope.external_holdout.v1",
            "kind": "external_blind_holdout",
            "evaluation_class": "external_calibration",
            "protocol": {
                "independent_from_rule_authoring": False,
                "ground_truth_prepared_without_breachscope_findings": True,
                "final_holdout_seen_before_rule_freeze": True,
            },
            "provenance": {
                "source": f"arniki/atomic-evtx@{SOURCE_COMMIT}:{scenario['source_directory']}",
                "acquired_at": acquired_at,
                "license_or_permission": "Public GitHub repository; EVTX bytes used transiently and not redistributed.",
                "notes": "Same 12 scenarios already observed in P2-11B and used for calibration.",
            },
            "files": files,
            "scenarios": [{
                "scenario_id": scenario_id,
                "source_files": source_files,
                "expected_techniques": [str(scenario["expected_technique"]).upper()],
            }],
        }
        manifest_path = case_dir / "manifest.yaml"
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
                                 encoding="utf-8", newline="\n")
        index_path = case_dir / "event-index.jsonl"
        run(sys.executable, str(evaluator), "index", "--manifest", str(manifest_path),
            "--corpus-root", str(scenario_dir), "--out", str(index_path), cwd=detector)
        labels_path = case_dir / "labels.jsonl"
        labels_hash = make_labels(index_path, labels_path)
        manifest["labels"] = {"sha256": labels_hash}
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
                                 encoding="utf-8", newline="\n")
        prepared.append({"scenario_id": scenario_id, "scenario_dir": scenario_dir,
                         "case_dir": case_dir, "manifest": manifest_path, "labels": labels_path})

    outcomes: list[dict] = []
    rules_seen: set[int] = set()
    totals = Counter()
    runtime_sum = 0.0
    peak_memory_max = 0.0
    technique_scenarios: Counter[str] = Counter()

    for item in prepared:
        result_path = item["case_dir"] / "result.json"
        run(sys.executable, str(evaluator), "score", "--repo", str(detector),
            "--manifest", str(item["manifest"]), "--corpus-root", str(item["scenario_dir"]),
            "--labels", str(item["labels"]), "--freeze", str(freeze),
            "--rules-dir", str(detector / "rules"), "--out", str(result_path), cwd=detector)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("schema") != "breachscope.external_holdout.result.v1":
            raise RuntimeError("unexpected evaluator result schema")
        if result["claim_boundary"]["evaluation_class"] != "external_calibration":
            raise RuntimeError("unexpected evaluation class")
        if int(result["corpus"]["scored_events"]) != 0:
            raise RuntimeError("calibration must not invent event-level scored labels")
        if int(result["corpus"]["ignored_events"]) != int(result["corpus"]["events"]):
            raise RuntimeError("all event labels must remain ignore")
        if int(result["scenarios"]["total"]) != 1:
            raise RuntimeError("per-scenario result must contain exactly one scenario")

        outcome = result["scenarios"]["outcomes"][0]
        if outcome["scenario_id"] != item["scenario_id"]:
            raise RuntimeError("scenario result order/id mismatch")
        observed = sorted(str(x) for x in outcome.get("observed_techniques", []))
        for technique in set(observed):
            technique_scenarios[technique] += 1
        rules_seen.add(int(result["detection"]["rules"]))
        totals["events"] += int(result["corpus"]["events"])
        totals["findings"] += int(result["detection"]["findings"])
        totals["flagged_events"] += int(result["detection"]["flagged_events"])
        totals["flagged_ignored_events"] += int(result["detection"]["flagged_ignored_events"])
        runtime_sum += float(result["performance"]["runtime_seconds"])
        peak_memory_max = max(peak_memory_max, float(result["performance"]["peak_memory_mb"]))
        outcomes.append({
            "scenario_id": outcome["scenario_id"],
            "expected_techniques": outcome["expected_techniques"],
            "observed_techniques": observed,
            "matched_techniques": outcome.get("matched_techniques", []),
            "missing_techniques": outcome.get("missing_techniques", []),
            "status": outcome["status"],
            "findings": int(result["detection"]["findings"]),
            "flagged_events": int(result["detection"]["flagged_events"]),
            "manifest_sha256": result["corpus"]["manifest_sha256"],
            "labels_sha256": result["corpus"]["labels_sha256"],
        })

    if rules_seen != {EXPECTED_RULE_COUNT}:
        raise RuntimeError(f"unexpected rule counts: {sorted(rules_seen)}")
    if totals["events"] != 902:
        raise RuntimeError(f"event count drift: expected 902, got {totals['events']}")

    hits = sum(row["status"] == "hit" for row in outcomes)
    aggregate = {
        "schema": "breachscope.p2_11h_external_calibration_result.v1",
        "evaluation_class": "external_calibration",
        "change_class": "wmic_query_telemetry_rule_addition",
        "detector_repo_commit": DETECTOR_COMMIT,
        "rules_tree_sha256": EXPECTED_RULE_TREE,
        "rule_file_count": 4,
        "rules": EXPECTED_RULE_COUNT,
        "source_repository": "arniki/atomic-evtx",
        "source_commit": SOURCE_COMMIT,
        "selection_frozen_commit": FROZEN_SELECTION_COMMIT,
        "scenario_total": len(outcomes),
        "scenario_hits": hits,
        "scenario_misses": len(outcomes) - hits,
        "scenario_hit_rate": hits / len(outcomes),
        "events": totals["events"],
        "findings": totals["findings"],
        "flagged_events": totals["flagged_events"],
        "flagged_ignored_events": totals["flagged_ignored_events"],
        "runtime_seconds_sum": runtime_sum,
        "peak_memory_mb_max": peak_memory_max,
        "observed_technique_scenario_counts": dict(sorted(technique_scenarios.items())),
        "outcomes": outcomes,
        "event_level": {
            "labels": "all_ignore", "scored_events": 0,
            "precision": "NOT_CLAIMED", "recall": "NOT_CLAIMED",
            "false_positive_rate": "NOT_CLAIMED",
        },
        "claim_boundary": {
            "final_blind_holdout": False,
            "fresh_external_baseline": False,
            "production_detection_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "note": "Same public Atomic-EVTX scenarios were already observed in P2-11B and used for calibration.",
        },
    }
    aggregate_path = out / "aggregate-result.json"
    aggregate_path.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                              encoding="utf-8", newline="\n")
    print(json.dumps(aggregate, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
