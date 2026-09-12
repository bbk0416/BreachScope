from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_12b_apt29_day1_binding.yaml"
RESULT = ROOT / "external_baseline" / "results" / "p2_12c_13eb8f6a" / "apt29-day1-result.json"
OUT = ROOT / "p2_12d_post_result_taxonomy.json"

ATTACK_COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
ATTACK_PATH = "enterprise-attack/enterprise-attack-19.2.json"
ATTACK_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{ATTACK_COMMIT}/{ATTACK_PATH}"
)


def _attack_external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def _parent_match(expected: str, observed: str) -> bool:
    return observed == expected or observed.startswith(expected + ".")


def main() -> int:
    binding = yaml.safe_load(BINDING.read_text(encoding="utf-8"))
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert binding["binding_id"] == "p2-12b-otrf-apt29-day1-v1"
    assert binding["protocol_state"]["day2_reserved_unscored"] is True
    assert result["evaluation_class"] == "fresh_external_holdout"
    assert result["events"] == 196081
    assert result["parse_errors"] == 0
    assert result["source_legacy_technique_total"] == 45
    assert result["exact_legacy_id_overlap"] == ["T1140"]
    assert result["exact_legacy_id_overlap_count"] == 1

    source_ids = list(binding["label_binding"]["technique_ids"])
    observed_ids = sorted(result["detected_technique_counts"])
    assert len(source_ids) == 45
    assert len(observed_ids) == 6

    with urllib.request.urlopen(ATTACK_URL, timeout=90) as response:
        attack_bytes = response.read()
    attack_sha = hashlib.sha256(attack_bytes).hexdigest()
    assert attack_sha == ATTACK_SHA256, (attack_sha, ATTACK_SHA256)
    attack = json.loads(attack_bytes)

    by_external: dict[str, dict[str, Any]] = {}
    by_stix: dict[str, dict[str, Any]] = {}
    revoked_by: dict[str, str] = {}

    for obj in attack["objects"]:
        if obj.get("type") == "attack-pattern":
            by_stix[obj["id"]] = obj
            ext = _attack_external_id(obj)
            if ext:
                by_external[ext] = obj
        elif obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_by[obj["source_ref"]] = obj["target_ref"]

    rows: list[dict[str, Any]] = []
    status_counts = {"active": 0, "revoked": 0, "deprecated": 0, "missing": 0}
    semantic_source_matches: list[dict[str, Any]] = []
    officially_replaced = 0

    for source_id in source_ids:
        obj = by_external.get(source_id)
        if obj is None:
            status_counts["missing"] += 1
            rows.append(
                {
                    "source_id": source_id,
                    "status_v19_2": "missing",
                    "official_replacement_chain": [],
                    "effective_current_id": None,
                    "matched_observed_ids": [],
                }
            )
            continue

        if obj.get("revoked", False):
            status = "revoked"
        elif obj.get("x_mitre_deprecated", False):
            status = "deprecated"
        else:
            status = "active"
        status_counts[status] += 1

        chain: list[str] = []
        current = obj
        seen: set[str] = set()
        while current.get("revoked", False):
            current_stix = current["id"]
            if current_stix in seen:
                raise AssertionError(f"revoked-by cycle at {source_id}")
            seen.add(current_stix)
            target_stix = revoked_by.get(current_stix)
            if target_stix is None:
                break
            target = by_stix[target_stix]
            target_ext = _attack_external_id(target)
            if target_ext is None:
                break
            chain.append(target_ext)
            current = target

        if chain:
            officially_replaced += 1

        if status == "active":
            effective = source_id
        elif chain and not current.get("revoked", False) and not current.get("x_mitre_deprecated", False):
            effective = chain[-1]
        else:
            effective = None

        matched = [] if effective is None else [x for x in observed_ids if _parent_match(effective, x)]
        row = {
            "source_id": source_id,
            "status_v19_2": status,
            "official_replacement_chain": chain,
            "effective_current_id": effective,
            "matched_observed_ids": matched,
        }
        rows.append(row)
        if matched:
            semantic_source_matches.append(row)

    matched_observed = sorted({x for row in semantic_source_matches for x in row["matched_observed_ids"]})
    unmatched_observed = sorted(set(observed_ids) - set(matched_observed))
    resolvable_source_ids = [row for row in rows if row["effective_current_id"] is not None]

    output = {
        "schema": "breachscope.p2_12d_day1_post_result_taxonomy.v1",
        "analysis_class": "post_result_descriptive_analysis",
        "fresh_result_record": "external_baseline/results/p2_12c_13eb8f6a/apt29-day1-result.json",
        "binding_record": "external_baseline/p2_12b_apt29_day1_binding.yaml",
        "day2_accessed": False,
        "attack_reference": {
            "repository": "mitre-attack/attack-stix-data",
            "commit": ATTACK_COMMIT,
            "release": "Enterprise ATT&CK v19.2",
            "path": ATTACK_PATH,
            "sha256": attack_sha,
            "mapping_rule": "Only exact active IDs and official STIX revoked-by relationships are used. Deprecated IDs without a revoked-by replacement are not guessed or silently remapped.",
        },
        "fresh_precommitted_result_preserved": {
            "source_legacy_id_total": 45,
            "exact_legacy_id_overlap": ["T1140"],
            "exact_legacy_id_overlap_count": 1,
            "exact_legacy_id_overlap_fraction": result["exact_legacy_id_overlap_fraction"],
            "interpretation": "Corpus-level exact source-label overlap only; not recall.",
        },
        "observed_detector_current_ids": observed_ids,
        "source_id_status_counts_v19_2": status_counts,
        "officially_replaced_source_id_count": officially_replaced,
        "resolvable_source_id_count": len(resolvable_source_ids),
        "post_result_semantic_source_match_count": len(semantic_source_matches),
        "post_result_semantic_source_matches": semantic_source_matches,
        "matched_observed_detector_ids": matched_observed,
        "unmatched_observed_detector_ids": unmatched_observed,
        "source_id_taxonomy": rows,
        "claim_boundary": {
            "fresh_primary_metric_recomputed": False,
            "post_result_semantic_match_is_fresh_metric": False,
            "production_detection_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
            "note": "This analysis was performed after the P2-12C Day 1 result was observed. It may explain ATT&CK-version drift, but it must not replace or improve the precommitted fresh 1/45 exact-overlap observation. Day 2 remains unseen and unscored.",
        },
    }

    OUT.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
