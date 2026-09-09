#!/usr/bin/env python3
"""Verify the recorded P2-09E external evidence benchmark without network access."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping

import yaml

SCHEMA = "breachscope.reproducible_detection_evidence_benchmark.v1"
DEFAULT_MANIFEST = "external_baseline/p2_09e_benchmark.yaml"


class BenchmarkError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise BenchmarkError(f"YAML mapping required: {path}")
    return data


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkError(f"mapping required: {label}")
    return value


def _relative_file(repo: Path, value: Any, label: str) -> Path:
    rel = Path(str(value or ""))
    if not str(rel) or rel.is_absolute() or ".." in rel.parts:
        raise BenchmarkError(f"safe repository-relative path required: {label}")
    path = (repo / rel).resolve()
    try:
        path.relative_to(repo.resolve())
    except ValueError as exc:
        raise BenchmarkError(f"path escapes repository: {label}") from exc
    if not path.is_file():
        raise BenchmarkError(f"file not found: {rel.as_posix()}")
    return path


def _rules_tree_hash(rules_dir: Path) -> tuple[str, int]:
    files = sorted(
        p
        for p in rules_dir.rglob("*")
        if p.is_file() and p.suffix.casefold() in {".yml", ".yaml"}
    )
    if not files:
        raise BenchmarkError(f"no YAML rule files found under {rules_dir}")
    h = hashlib.sha256()
    for path in files:
        rel = path.relative_to(rules_dir).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        canonical = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        h.update(hashlib.sha256(canonical).hexdigest().encode("ascii"))
        h.update(b"\0")
    return h.hexdigest(), len(files)


def _require(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise BenchmarkError(f"{label}: expected {expected!r}, got {actual!r}")


def _require_float(actual: Any, expected: Any, label: str) -> None:
    try:
        actual_f = float(actual)
        expected_f = float(expected)
    except (TypeError, ValueError) as exc:
        raise BenchmarkError(f"{label}: numeric value required") from exc
    if not math.isclose(actual_f, expected_f, rel_tol=1e-12, abs_tol=1e-15):
        raise BenchmarkError(f"{label}: expected {expected_f!r}, got {actual_f!r}")


def _verify_attack(
    repo: Path,
    component: Mapping[str, Any],
    common_rule_hash: str,
) -> tuple[dict[str, Any], list[Path]]:
    source_path = _relative_file(repo, component.get("source_contract"), "attack source_contract")
    result_path = _relative_file(repo, component.get("result_record"), "attack result_record")
    source = _load_yaml(source_path)
    result = _load_yaml(result_path)
    expected = _mapping(component.get("expected_metrics"), "attack expected_metrics")

    baseline_id = str(component.get("baseline_id") or "")
    measured_commit = str(component.get("evaluated_repo_commit") or "")
    rule_hash = str(component.get("rules_tree_sha256") or "")

    _require(source.get("baseline_id"), baseline_id, "attack source baseline_id")
    _require(result.get("baseline_id"), baseline_id, "attack result baseline_id")
    _require(result.get("evaluated_repo_commit"), measured_commit, "attack measured commit")
    _require(rule_hash, common_rule_hash, "attack component rule hash")
    _require(result.get("rules_tree_sha256"), common_rule_hash, "attack result rule hash")
    _require(result.get("evaluation_class"), "external_baseline", "attack evaluation_class")

    assets = source.get("assets")
    if not isinstance(assets, list):
        raise BenchmarkError("attack source assets must be a list")
    _require(len(assets), int(expected["source_files"]), "attack source file count")

    corpus = _mapping(result.get("corpus"), "attack result corpus")
    metrics = _mapping(result.get("primary_metrics"), "attack primary_metrics")
    observation = _mapping(result.get("detection_observation"), "attack detection_observation")
    claims = _mapping(result.get("claim_boundary"), "attack claim_boundary")

    _require(int(corpus.get("source_files", -1)), int(expected["source_files"]), "attack result source files")
    _require(int(corpus.get("events", -1)), int(expected["events"]), "attack events")
    _require(int(metrics.get("scenario_hits", -1)), int(expected["scenario_hits"]), "attack scenario hits")
    _require(int(metrics.get("scenario_misses", -1)), int(expected["scenario_misses"]), "attack scenario misses")
    _require(int(metrics.get("scenario_total", -1)), int(expected["scenario_total"]), "attack scenario total")
    _require_float(metrics.get("scenario_hit_rate"), expected["scenario_hit_rate"], "attack scenario hit rate")
    _require(int(observation.get("findings", -1)), int(expected["findings"]), "attack findings")
    _require(
        int(metrics.get("scenario_hits", 0)) + int(metrics.get("scenario_misses", 0)),
        int(metrics.get("scenario_total", -1)),
        "attack scenario accounting",
    )
    _require(
        claims.get("event_level_precision_recall_fpr"),
        "NOT_CLAIMED",
        "attack event-level precision/recall/FPR boundary",
    )
    _require(claims.get("final_blind_holdout"), False, "attack final blind holdout boundary")

    return {
        "baseline_id": baseline_id,
        "evaluated_repo_commit": measured_commit,
        "scenario_hits": int(metrics["scenario_hits"]),
        "scenario_total": int(metrics["scenario_total"]),
        "scenario_hit_rate": float(metrics["scenario_hit_rate"]),
        "events": int(corpus["events"]),
        "findings": int(observation["findings"]),
    }, [source_path, result_path]


def _verify_benign(
    repo: Path,
    component: Mapping[str, Any],
    common_rule_hash: str,
) -> tuple[dict[str, Any], list[Path]]:
    source_path = _relative_file(repo, component.get("source_contract"), "benign source_contract")
    result_path = _relative_file(repo, component.get("result_record"), "benign result_record")
    source = _load_yaml(source_path)
    result = _load_yaml(result_path)
    expected = _mapping(component.get("expected_metrics"), "benign expected_metrics")

    baseline_id = str(component.get("baseline_id") or "")
    measured_commit = str(component.get("evaluated_repo_commit") or "")
    rule_hash = str(component.get("rules_tree_sha256") or "")

    _require(source.get("baseline_id"), baseline_id, "benign source baseline_id")
    _require(result.get("baseline_id"), baseline_id, "benign result baseline_id")
    _require(result.get("evaluated_repo_commit"), measured_commit, "benign measured commit")
    _require(rule_hash, common_rule_hash, "benign component rule hash")
    _require(result.get("rules_tree_sha256"), common_rule_hash, "benign result rule hash")
    _require(result.get("evaluation_class"), "external_baseline", "benign evaluation_class")
    _require(result.get("label_policy"), "benign_by_source_intent", "benign label policy")

    source_record = _mapping(source.get("source"), "benign source")
    corpus = _mapping(result.get("corpus"), "benign result corpus")
    metrics = _mapping(result.get("primary_metrics"), "benign primary_metrics")
    claims = _mapping(result.get("claim_boundary"), "benign claim_boundary")

    _require(source_record.get("sha256"), corpus.get("sha256"), "benign corpus SHA consistency")
    _require(int(source_record.get("size", -1)), int(corpus.get("asset_size_bytes", -2)), "benign corpus size consistency")
    _require(int(corpus.get("source_evtx_files_total", -1)), int(expected["source_evtx_files_total"]), "benign source file count")
    _require(int(corpus.get("source_evtx_files_with_events", -1)), int(expected["source_evtx_files_with_events"]), "benign non-empty source file count")
    _require(int(corpus.get("events", -1)), int(expected["events"]), "benign events")
    _require(int(metrics.get("false_positives", -1)), int(expected["false_positives"]), "benign false positives")
    _require(int(metrics.get("true_negatives", -1)), int(expected["true_negatives"]), "benign true negatives")
    _require(int(metrics.get("findings", -1)), int(expected["findings"]), "benign findings")
    _require_float(metrics.get("false_positive_rate"), expected["false_positive_rate"], "benign FPR")

    fp = int(metrics["false_positives"])
    tn = int(metrics["true_negatives"])
    events = int(corpus["events"])
    _require(fp + tn, events, "benign confusion accounting")
    _require_float(fp / events, metrics["false_positive_rate"], "benign recomputed FPR")
    _require(claims.get("production_false_positive_rate"), "NOT_CLAIMED", "benign production FPR boundary")
    _require(claims.get("enterprise_environment_representative"), False, "benign enterprise representativeness boundary")
    _require(claims.get("event_level_manual_adjudication"), False, "benign manual adjudication boundary")

    return {
        "baseline_id": baseline_id,
        "evaluated_repo_commit": measured_commit,
        "events": events,
        "false_positives": fp,
        "true_negatives": tn,
        "false_positive_rate": float(metrics["false_positive_rate"]),
        "findings": int(metrics["findings"]),
    }, [source_path, result_path]


def verify(repo: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _load_yaml(manifest_path)
    _require(manifest.get("schema"), SCHEMA, "benchmark schema")
    _require(manifest.get("benchmark_type"), "detection_evidence_not_performance", "benchmark type")

    common = _mapping(manifest.get("common_detection_contract"), "common_detection_contract")
    common_rule_hash = str(common.get("rules_tree_sha256") or "")
    if len(common_rule_hash) != 64:
        raise BenchmarkError("common rules_tree_sha256 must be a full SHA-256")
    _require(common.get("commit_range_detection_semantics_changed"), False, "commit-range detection semantics boundary")

    current_rule_hash, rule_file_count = _rules_tree_hash(repo / "rules")
    _require(current_rule_hash, common_rule_hash, "current rule tree hash")

    components = _mapping(manifest.get("components"), "components")
    attack_component = _mapping(components.get("attack_external_baseline"), "attack component")
    benign_component = _mapping(components.get("benign_external_baseline"), "benign component")

    attack, attack_files = _verify_attack(repo, attack_component, common_rule_hash)
    benign, benign_files = _verify_benign(repo, benign_component, common_rule_hash)

    top_claims = _mapping(manifest.get("claim_boundary"), "benchmark claim_boundary")
    _require(top_claims.get("production_accuracy"), "NOT_CLAIMED", "benchmark production accuracy boundary")
    _require(top_claims.get("production_false_positive_rate"), "NOT_CLAIMED", "benchmark production FPR boundary")
    _require(top_claims.get("final_blind_holdout"), False, "benchmark final blind holdout boundary")
    _require(top_claims.get("performance_benchmark"), "NOT_CLAIMED", "benchmark performance boundary")

    evidence_paths = [manifest_path, *attack_files, *benign_files]
    h = hashlib.sha256()
    for path in sorted(evidence_paths, key=lambda p: p.relative_to(repo).as_posix()):
        rel = path.relative_to(repo).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(_sha256(path).encode("ascii"))
        h.update(b"\0")

    return {
        "schema": "breachscope.reproducible_detection_evidence_benchmark_verification.v1",
        "benchmark_id": manifest.get("benchmark_id"),
        "status": "PASS",
        "rules_tree_sha256": current_rule_hash,
        "rule_file_count": rule_file_count,
        "evidence_bundle_sha256": h.hexdigest(),
        "attack": attack,
        "benign": benign,
        "claim_boundary": {
            "production_accuracy": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "performance_benchmark": "NOT_CLAIMED",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--json", action="store_true", help="print machine-readable verification JSON")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    manifest_path = _relative_file(repo, args.manifest, "benchmark manifest")
    try:
        result = verify(repo, manifest_path)
    except BenchmarkError as exc:
        print(f"P2-09E benchmark verification: FAIL: {exc}")
        return 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        attack = result["attack"]
        benign = result["benign"]
        print("P2-09E benchmark verification: PASS")
        print(f"Rules SHA-256: {result['rules_tree_sha256']}")
        print(
            "Attack external baseline: "
            f"{attack['scenario_hits']}/{attack['scenario_total']} scenario hits "
            f"({attack['scenario_hit_rate']:.1%})"
        )
        print(
            "Benign external baseline: "
            f"FP={benign['false_positives']} TN={benign['true_negatives']} "
            f"FPR={benign['false_positive_rate']:.8%}"
        )
        print(f"Evidence bundle SHA-256: {result['evidence_bundle_sha256']}")
        print("Production accuracy/FPR: NOT CLAIMED")
        print("Performance benchmark: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
