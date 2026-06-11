"""Rule-pack coverage and catalog helpers."""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .attack import CORE_WINDOWS_TECHNIQUES, TACTIC_ORDER, get_mitre_name, get_mitre_tactic
from .schemas import Rule

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def summarize_rules(rules: Iterable[Rule]) -> dict[str, Any]:
    """Create a compact rule-pack coverage summary for reports and APIs."""
    rule_list = list(rules or [])
    by_severity = Counter((r.severity or "unknown").lower() for r in rule_list)
    by_tactic: dict[str, list[Rule]] = defaultdict(list)
    by_technique: dict[str, list[Rule]] = defaultdict(list)
    unmapped: list[str] = []

    for rule in rule_list:
        technique = (rule.mitre_technique or "unknown").upper()
        tactic = get_mitre_tactic(technique if technique != "UNKNOWN" else None)
        by_tactic[tactic].append(rule)
        if technique == "UNKNOWN":
            unmapped.append(rule.id)
        else:
            by_technique[technique].append(rule)

    tactic_rows = []
    for tactic, items in by_tactic.items():
        sev_counts = Counter((r.severity or "unknown").lower() for r in items)
        highest = max(sev_counts.keys(), key=lambda sev: SEVERITY_ORDER.get(sev, 0)) if sev_counts else "unknown"
        tactic_rows.append({
            "tactic": tactic,
            "rules": len(items),
            "techniques": sorted({(r.mitre_technique or "unknown").upper() for r in items}),
            "highest_severity": highest,
            "severity_counts": dict(sev_counts),
        })

    order_index = {name: idx for idx, name in enumerate(TACTIC_ORDER)}
    tactic_rows.sort(key=lambda row: (order_index.get(str(row["tactic"]), 999), -int(row["rules"])))

    technique_rows = []
    for technique, items in by_technique.items():
        sev_counts = Counter((r.severity or "unknown").lower() for r in items)
        highest = max(sev_counts.keys(), key=lambda sev: SEVERITY_ORDER.get(sev, 0)) if sev_counts else "unknown"
        technique_rows.append({
            "technique": technique,
            "name": get_mitre_name(technique),
            "tactic": get_mitre_tactic(technique),
            "rules": len(items),
            "highest_severity": highest,
        })
    technique_rows.sort(key=lambda row: (str(row["tactic"]), str(row["technique"])))

    covered_core = sorted(set(by_technique).intersection(CORE_WINDOWS_TECHNIQUES))
    missing_core = [tech for tech in CORE_WINDOWS_TECHNIQUES if tech not in by_technique]

    return {
        "total_rules": len(rule_list),
        "mapped_rules": len(rule_list) - len(unmapped),
        "unmapped_rules": unmapped,
        "unique_techniques": len(by_technique),
        "severity_counts": dict(by_severity),
        "tactic_coverage": tactic_rows,
        "technique_coverage": technique_rows,
        "covered_core_techniques": covered_core,
        "missing_core_techniques": [
            {"technique": tech, "name": get_mitre_name(tech), "tactic": get_mitre_tactic(tech)}
            for tech in missing_core
        ],
        "coverage_percent_core_windows": round((len(covered_core) / len(CORE_WINDOWS_TECHNIQUES)) * 100, 1) if CORE_WINDOWS_TECHNIQUES else 0.0,
    }


def export_rule_catalog_csv(rules: Iterable[Rule], out_csv: Path) -> Path:
    """Export the loaded rules as a reviewer-friendly CSV catalog."""
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "id",
            "name",
            "severity",
            "mitre_technique",
            "mitre_name",
            "tactic",
            "operator",
            "field",
            "pattern",
            "description",
        ])
        for rule in sorted(list(rules or []), key=lambda r: (r.id, r.name)):
            writer.writerow([
                rule.id,
                rule.name,
                rule.severity,
                rule.mitre_technique or "",
                get_mitre_name(rule.mitre_technique),
                get_mitre_tactic(rule.mitre_technique),
                rule.operator or "regex",
                ",".join(rule.fields or [rule.field]),
                rule.pattern,
                rule.description,
            ])
    return out_csv
