from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from breachscope.analyzer import apply_rules
from breachscope.correlator import correlate_events
from breachscope.rules import load_rules
from breachscope.scenario import infer_scenarios
from breachscope.utils import get_event_identity_key
from scripts.evaluate_external_holdout import _record_to_event, rules_tree_hash

EXPECTED_ARCHIVE_SHA256 = "ab4d1ec4e44102c87946a974f93aa248e49e5001e01fac3f137ec7e61bbc18ed"
EXPECTED_MEMBER = "empire_apt3_2019-05-14223117.json"
FROZEN_PRODUCT_COMMIT = "4514279c0b223483016acf35009ed2985f6a016e"
EXPECTED_RULES_SHA256 = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
DOCUMENTED_SOURCE_HOST = "HR001"
DOCUMENTED_TARGET_HOST = "HFDC01"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _short_host(value: object) -> str:
    text = str(value or "").strip()
    return text.split(".", 1)[0].upper() if text else ""


def _load_events(archive: Path) -> tuple[list, int, Counter]:
    events = []
    parse_errors = 0
    hosts: Counter[str] = Counter()
    with tarfile.open(archive, "r:gz") as tf:
        members = [member for member in tf.getmembers() if member.isfile()]
        if [member.name for member in members] != [EXPECTED_MEMBER]:
            raise RuntimeError(f"unexpected archive members: {[member.name for member in members]}")
        handle = tf.extractfile(members[0])
        if handle is None:
            raise RuntimeError("archive member could not be opened")
        with handle:
            for line in handle:
                try:
                    event = _record_to_event(json.loads(line))
                except Exception:
                    parse_errors += 1
                    continue
                events.append(event)
                hosts[_short_host(event.host)] += 1
    return events, parse_errors, hosts


def _assert_frozen_product(repo: Path) -> None:
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", f"{FROZEN_PRODUCT_COMMIT}..HEAD", "--", "breachscope", "rules"],
        cwd=repo, text=True,
    ).strip()
    if changed:
        raise RuntimeError(f"frozen product tree changed after binding: {changed}")


def _canonical_coverage(events: list) -> dict:
    total = len(events)
    return {
        "events": total,
        "host_nonempty": sum(bool(str(getattr(event, "host", "") or "").strip()) for event in events),
        "source_nonempty": sum(bool(str(getattr(event, "source", "") or "").strip()) for event in events),
        "raw_computer_name_present": sum(isinstance(getattr(event, "raw", None), dict) and bool(event.raw.get("computer_name")) for event in events),
        "raw_source_name_present": sum(isinstance(getattr(event, "raw", None), dict) and bool(event.raw.get("source_name")) for event in events),
        "raw_record_number_present": sum(isinstance(getattr(event, "raw", None), dict) and bool(event.raw.get("record_number")) for event in events),
    }


def _chain_row(chain) -> dict:
    hosts = sorted({_short_host(event.host) for event in chain.events if _short_host(event.host)})
    return {
        "chain_id": chain.chain_id,
        "chain_type": chain.chain_type,
        "event_count": len(chain.events),
        "finding_count": len(chain.findings),
        "hosts": hosts,
        "start_time": chain.start_time.isoformat() if chain.start_time else None,
        "end_time": chain.end_time.isoformat() if chain.end_time else None,
        "confidence": chain.confidence,
        "metadata": dict(getattr(chain, "metadata", {}) or {}),
    }


def _scenario_row(scenario) -> dict:
    hosts = sorted({_short_host(event.host) for chain in scenario.chains for event in chain.events if _short_host(event.host)})
    return {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "attack_stage": scenario.attack_stage,
        "confidence": scenario.confidence,
        "mitre_techniques": sorted(str(value) for value in scenario.mitre_techniques),
        "chain_count": len(scenario.chains),
        "hosts": hosts,
    }


def evaluate(repo: Path, archive: Path) -> dict:
    _assert_frozen_product(repo)
    archive_sha = _sha256(archive)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise RuntimeError(f"archive SHA-256 mismatch: {archive_sha} != {EXPECTED_ARCHIVE_SHA256}")

    timings = {}
    started = time.perf_counter()
    events, parse_errors, hosts = _load_events(archive)
    timings["load"] = time.perf_counter() - started

    rules = load_rules(repo / "rules")
    rules_sha, rule_file_count = rules_tree_hash(repo / "rules")
    if rules_sha != EXPECTED_RULES_SHA256:
        raise RuntimeError(f"rules SHA-256 mismatch: {rules_sha} != {EXPECTED_RULES_SHA256}")
    canonical_coverage = _canonical_coverage(events)

    started = time.perf_counter()
    findings = list(apply_rules(events, rules))
    timings["detection"] = time.perf_counter() - started
    flagged_keys = {get_event_identity_key(finding.event) for finding in findings}
    finding_hosts = Counter(_short_host(finding.event.host) for finding in findings)

    started = time.perf_counter()
    chains = correlate_events(events, findings)
    timings["correlation"] = time.perf_counter() - started
    chain_rows = [_chain_row(chain) for chain in chains]
    chain_types = Counter(row["chain_type"] for row in chain_rows)
    cross_host_chains = [row for row in chain_rows if len(row["hosts"]) > 1]

    started = time.perf_counter()
    scenarios = infer_scenarios(chains, findings)
    timings["scenario"] = time.perf_counter() - started
    scenario_rows = [_scenario_row(scenario) for scenario in scenarios]
    cross_host_scenarios = [row for row in scenario_rows if len(row["hosts"]) > 1]

    documented_pair = {DOCUMENTED_SOURCE_HOST, DOCUMENTED_TARGET_HOST}
    pair_chains = [row for row in cross_host_chains if documented_pair.issubset(set(row["hosts"]))]
    pair_scenarios = [row for row in cross_host_scenarios if documented_pair.issubset(set(row["hosts"]))]
    largest = sorted(chain_rows, key=lambda row: row["event_count"], reverse=True)[:20]

    return {
        "schema": "breachscope.p2_16b_external_reconstruction_holdout.v1",
        "analysis_class": "independent_external_reconstruction_holdout_one_pass",
        "measurement_repo_commit": os.popen(f'git -C "{repo}" rev-parse HEAD').read().strip(),
        "frozen_product_commit": FROZEN_PRODUCT_COMMIT,
        "archive_sha256": archive_sha,
        "archive_member": EXPECTED_MEMBER,
        "events": len(events),
        "parse_errors": parse_errors,
        "hosts": dict(sorted(hosts.items())),
        "canonical_coverage": canonical_coverage,
        "product_tree_matches_frozen_commit": True,
        "rules": len(rules),
        "rule_file_count": rule_file_count,
        "rules_tree_sha256": rules_sha,
        "findings": len(findings),
        "flagged_events": len(flagged_keys),
        "finding_hosts": dict(sorted(finding_hosts.items())),
        "chains": len(chains),
        "chain_types": dict(sorted(chain_types.items())),
        "cross_host_chains": len(cross_host_chains),
        "documented_hr001_hfdc01_chains": len(pair_chains),
        "documented_hr001_hfdc01_chain_rows": pair_chains,
        "largest_chains": largest,
        "scenarios": len(scenarios),
        "cross_host_scenarios": len(cross_host_scenarios),
        "documented_hr001_hfdc01_scenarios": len(pair_scenarios),
        "documented_hr001_hfdc01_scenario_rows": pair_scenarios,
        "scenario_rows": scenario_rows,
        "timing_seconds": {key: round(value, 6) for key, value in timings.items()},
        "claim_boundary": {
            "event_level_ground_truth": "NOT_AVAILABLE",
            "detection_precision": "NOT_CLAIMED",
            "detection_recall": "NOT_CLAIMED",
            "chain_precision": "NOT_CLAIMED",
            "chain_recall": "NOT_CLAIMED",
            "scenario_precision": "NOT_CLAIMED",
            "scenario_recall": "NOT_CLAIMED",
            "scenario_accuracy": "NOT_CLAIMED",
            "production_quality": "NOT_CLAIMED",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=ROOT)
    args = parser.parse_args()
    result = evaluate(args.repo.resolve(), args.archive.resolve())
    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("Observation written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
