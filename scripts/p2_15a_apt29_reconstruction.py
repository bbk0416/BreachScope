from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import zipfile
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

EXPECTED_ARCHIVE_SHA256 = (
    "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5"
)


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
    with zipfile.ZipFile(archive) as zf:
        members = [name for name in zf.namelist() if not name.endswith("/")]
        if len(members) != 1:
            raise RuntimeError(f"expected one archive member, got {len(members)}")
        with zf.open(members[0], "r") as handle:
            for line in handle:
                try:
                    event = _record_to_event(json.loads(line))
                except Exception:
                    parse_errors += 1
                    continue
                events.append(event)
                hosts[_short_host(event.host)] += 1
    return events, parse_errors, hosts


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
    }


def _scenario_row(scenario) -> dict:
    hosts = sorted({
        _short_host(event.host)
        for chain in scenario.chains
        for event in chain.events
        if _short_host(event.host)
    })
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
    archive_sha = _sha256(archive)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise RuntimeError(
            f"archive SHA-256 mismatch: {archive_sha} != {EXPECTED_ARCHIVE_SHA256}"
        )

    timings = {}
    started = time.perf_counter()
    events, parse_errors, hosts = _load_events(archive)
    timings["load"] = time.perf_counter() - started

    rules = load_rules(repo / "rules")
    rules_sha, rule_file_count = rules_tree_hash(repo / "rules")

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

    scranton_nashua = {"SCRANTON", "NASHUA"}
    largest = sorted(chain_rows, key=lambda row: row["event_count"], reverse=True)[:20]

    return {
        "schema": "breachscope.p2_15a_external_reconstruction_observation.v1",
        "analysis_class": "post_hoc_external_reconstruction_diagnostic",
        "repo_commit": os.popen(f'git -C "{repo}" rev-parse HEAD').read().strip(),
        "archive_sha256": archive_sha,
        "events": len(events),
        "parse_errors": parse_errors,
        "hosts": dict(sorted(hosts.items())),
        "rules": len(rules),
        "rule_file_count": rule_file_count,
        "rules_tree_sha256": rules_sha,
        "findings": len(findings),
        "flagged_events": len(flagged_keys),
        "finding_hosts": dict(sorted(finding_hosts.items())),
        "chains": len(chains),
        "chain_types": dict(sorted(chain_types.items())),
        "cross_host_chains": len(cross_host_chains),
        "scranton_nashua_chains": sum(
            scranton_nashua.issubset(set(row["hosts"])) for row in chain_rows
        ),
        "largest_chains": largest,
        "scenarios": len(scenarios),
        "cross_host_scenarios": len(cross_host_scenarios),
        "scranton_nashua_scenarios": sum(
            scranton_nashua.issubset(set(row["hosts"])) for row in scenario_rows
        ),
        "scenario_rows": scenario_rows,
        "timing_seconds": {key: round(value, 6) for key, value in timings.items()},
        "claim_boundary": {
            "event_level_chain_ground_truth": "NOT_AVAILABLE",
            "chain_precision": "NOT_CLAIMED",
            "chain_recall": "NOT_CLAIMED",
            "scenario_accuracy": "NOT_CLAIMED",
            "production_quality": "NOT_CLAIMED",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    repo = args.repo.resolve()
    archive = args.archive.resolve()
    out = args.out.resolve()
    result = evaluate(repo, archive)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("Observation written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
