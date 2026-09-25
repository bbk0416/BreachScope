"""Pure scoring semantics for the preregistered MITRE BRAWL attack holdout.

This module contains no raw BRAWL archive access. It scores already-normalized
BreachScope findings against BSF attack steps extracted by
breachscope.brawl.extract_bsf_steps().
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from .schemas import Finding


LEGACY_ATTACK_CROSSWALK: dict[str, str] = {
    "T1087": "T1087",
    "T1003": "T1003",
    "T1016": "T1016",
    "T1069": "T1069",
    "T1086": "T1059.001",
    "T1060": "T1547.001",
    "T1105": "T1105",
    "T1018": "T1018",
    "T1077": "T1021.002",
    "T1047": "T1047",
}

EXACT_TIME_TOLERANCE_SECONDS = 1


class BrawlScoringError(ValueError):
    """Raised when preregistered BRAWL ground truth cannot be scored safely."""


def _parse_time(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise BrawlScoringError("missing timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise BrawlScoringError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_host(value: Any) -> str:
    return str(value or "").strip().rstrip(".").casefold()


def hosts_equivalent(left: Any, right: Any) -> bool:
    a = normalize_host(left)
    b = normalize_host(right)
    if not a or not b:
        return False
    if a == b:
        return True

    a_short = a.split(".", 1)[0]
    b_short = b.split(".", 1)[0]
    if a_short != b_short:
        return False

    # The public BRAWL game documents one brawlco.com Windows enterprise.
    # Accept a short-host/FQDN representation difference, but never collapse
    # two distinct FQDNs merely because their first DNS labels are equal.
    a_fqdn = "." in a
    b_fqdn = "." in b
    return a_fqdn != b_fqdn


def event_bounds(event: Mapping[str, Any]) -> tuple[datetime, datetime]:
    exact = event.get("time")
    if exact not in (None, ""):
        center = _parse_time(exact)
        delta = timedelta(seconds=EXACT_TIME_TOLERANCE_SECONDS)
        return center - delta, center + delta

    after = event.get("happened_after")
    before = event.get("happened_before")
    if after in (None, "") and before in (None, ""):
        raise BrawlScoringError("BSF event has no time or happened_after/happened_before")

    if after not in (None, ""):
        lower = _parse_time(after)
    else:
        upper_only = _parse_time(before)
        lower = upper_only - timedelta(seconds=EXACT_TIME_TOLERANCE_SECONDS)

    if before not in (None, ""):
        upper = _parse_time(before)
    else:
        lower_only = _parse_time(after)
        upper = lower_only + timedelta(seconds=EXACT_TIME_TOLERANCE_SECONDS)

    if lower > upper:
        raise BrawlScoringError("BSF happened_after is later than happened_before")
    return lower, upper


def referenced_event_windows(step: Mapping[str, Any]) -> list[dict[str, Any]]:
    events = step.get("events")
    if not isinstance(events, list) or not events:
        raise BrawlScoringError("step has no referenced BSF events")

    windows: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise BrawlScoringError(f"referenced BSF event {index} is not an object")
        host = normalize_host(event.get("host"))
        if not host:
            raise BrawlScoringError(f"referenced BSF event {index} has no host")
        lower, upper = event_bounds(event)
        windows.append(
            {
                "event_id": str(event.get("id") or ""),
                "host": host,
                "lower": lower,
                "upper": upper,
            }
        )
    return windows


def step_window(step: Mapping[str, Any]) -> tuple[datetime, datetime]:
    """Diagnostic outer bounds only; matching never uses this convex hull."""
    windows = referenced_event_windows(step)
    return (
        min(item["lower"] for item in windows),
        max(item["upper"] for item in windows),
    )


def expected_technique_pairs(step: Mapping[str, Any]) -> list[dict[str, str | None]]:
    techniques = step.get("techniques")
    if not isinstance(techniques, list) or not techniques:
        raise BrawlScoringError("step has no ATT&CK technique")

    pairs: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for item in techniques:
        if not isinstance(item, Mapping):
            continue
        upstream = str(item.get("technique_id") or "").strip().upper()
        if not upstream or upstream in seen:
            continue
        seen.add(upstream)
        pairs.append(
            {
                "upstream_technique": upstream,
                "expected_current_technique": LEGACY_ATTACK_CROSSWALK.get(upstream),
            }
        )

    if not pairs:
        raise BrawlScoringError("step has no ATT&CK technique")
    return pairs


def expected_techniques(step: Mapping[str, Any]) -> list[str]:
    return [
        str(pair["expected_current_technique"])
        for pair in expected_technique_pairs(step)
        if pair["expected_current_technique"]
    ]


def technique_matches(expected: str, observed: str) -> bool:
    expected = str(expected or "").strip().upper()
    observed = str(observed or "").strip().upper()
    if not expected or not observed:
        return False
    if observed == expected:
        return True

    # A current sub-technique satisfies an upstream parent label. The reverse
    # is deliberately forbidden because it would broaden a specific label.
    return "." not in expected and observed.startswith(expected + ".")


def finding_techniques(finding: Finding) -> list[str]:
    values = list(getattr(finding, "mitre_techniques", ()) or ())
    if not values and finding.mitre_technique not in (None, ""):
        values = [str(finding.mitre_technique)]
    return [str(value).strip().upper() for value in values if str(value).strip()]


def _finding_matches_pair(
    finding: Finding,
    *,
    expected: str,
    windows: list[dict[str, Any]],
) -> bool:
    if not any(
        technique_matches(expected, observed)
        for observed in finding_techniques(finding)
    ):
        return False

    try:
        timestamp = _parse_time(finding.event.timestamp)
    except BrawlScoringError:
        return False

    for window in windows:
        if not hosts_equivalent(finding.event.host, window["host"]):
            continue
        if window["lower"] <= timestamp <= window["upper"]:
            return True
    return False


def _finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "finding_techniques": finding_techniques(finding),
        "host": finding.event.host,
        "timestamp": finding.event.timestamp,
    }


def score_brawl_steps(
    steps: Iterable[Mapping[str, Any]],
    findings: Iterable[Finding],
) -> dict[str, Any]:
    """Score frozen BSF step-technique pairs without calling the result recall."""
    finding_list = list(findings)
    pair_rows: list[dict[str, Any]] = []
    step_rows: list[dict[str, Any]] = []

    for step in steps:
        step_id = str(step.get("step_id") or "")
        try:
            if not step_id:
                raise BrawlScoringError("step_id is missing")
            pairs = expected_technique_pairs(step)
            windows = referenced_event_windows(step)
        except BrawlScoringError as exc:
            raw_techniques = step.get("techniques")
            upstream = [
                str(item.get("technique_id") or "").strip().upper()
                for item in raw_techniques
                if isinstance(raw_techniques, list)
                and isinstance(item, Mapping)
                and str(item.get("technique_id") or "").strip()
            ]
            if not upstream:
                upstream = [""]
            for technique in upstream:
                pair_rows.append(
                    {
                        "step_id": step_id,
                        "upstream_technique": technique,
                        "expected_current_technique": LEGACY_ATTACK_CROSSWALK.get(technique),
                        "status": "ERROR",
                        "error": str(exc),
                        "matching_findings": [],
                    }
                )
            step_rows.append(
                {
                    "step_id": step_id,
                    "status": "ERROR",
                    "pair_count": len(upstream),
                    "pair_hits": 0,
                    "pair_misses": 0,
                    "pair_errors": len(upstream),
                    "error": str(exc),
                }
            )
            continue

        step_pair_rows: list[dict[str, Any]] = []
        for pair in pairs:
            upstream = str(pair["upstream_technique"] or "")
            expected_value = pair["expected_current_technique"]
            if not expected_value:
                row = {
                    "step_id": step_id,
                    "upstream_technique": upstream,
                    "expected_current_technique": None,
                    "status": "ERROR",
                    "error": f"unmapped upstream ATT&CK technique: {upstream}",
                    "matching_findings": [],
                }
            else:
                expected = str(expected_value)
                matches = [
                    finding
                    for finding in finding_list
                    if _finding_matches_pair(
                        finding,
                        expected=expected,
                        windows=windows,
                    )
                ]
                row = {
                    "step_id": step_id,
                    "upstream_technique": upstream,
                    "expected_current_technique": expected,
                    "status": "HIT" if matches else "MISS",
                    "referenced_event_windows": [
                        {
                            "event_id": item["event_id"],
                            "host": item["host"],
                            "window_start": item["lower"].isoformat(),
                            "window_end": item["upper"].isoformat(),
                        }
                        for item in windows
                    ],
                    "matching_findings": [_finding_summary(finding) for finding in matches],
                }
            pair_rows.append(row)
            step_pair_rows.append(row)

        statuses = [row["status"] for row in step_pair_rows]
        hits = statuses.count("HIT")
        misses = statuses.count("MISS")
        errors = statuses.count("ERROR")
        if errors:
            step_status = "ERROR"
        elif hits == len(statuses):
            step_status = "HIT"
        elif hits:
            step_status = "PARTIAL"
        else:
            step_status = "MISS"

        step_rows.append(
            {
                "step_id": step_id,
                "status": step_status,
                "pair_count": len(statuses),
                "pair_hits": hits,
                "pair_misses": misses,
                "pair_errors": errors,
            }
        )

    pair_hits = sum(row["status"] == "HIT" for row in pair_rows)
    pair_misses = sum(row["status"] == "MISS" for row in pair_rows)
    pair_errors = sum(row["status"] == "ERROR" for row in pair_rows)
    total_pairs = len(pair_rows)
    evaluable_pairs = pair_hits + pair_misses

    step_hits = sum(row["status"] == "HIT" for row in step_rows)
    step_partial = sum(row["status"] == "PARTIAL" for row in step_rows)
    step_misses = sum(row["status"] == "MISS" for row in step_rows)
    step_errors = sum(row["status"] == "ERROR" for row in step_rows)
    total_steps = len(step_rows)
    evaluable_steps = step_hits + step_partial + step_misses

    return {
        "metric_name": "brawl_attack_step_technique_hit_fraction",
        "pair_rows": pair_rows,
        "step_rows": step_rows,
        "counts": {
            "total_step_technique_pairs": total_pairs,
            "pair_hits": pair_hits,
            "pair_misses": pair_misses,
            "pair_errors": pair_errors,
            "evaluable_pairs": evaluable_pairs,
            "total_steps": total_steps,
            "fully_hit_steps": step_hits,
            "partial_steps": step_partial,
            "missed_steps": step_misses,
            "error_steps": step_errors,
            "evaluable_steps": evaluable_steps,
        },
        "step_technique_hit_fraction_of_all_pairs": (
            pair_hits / total_pairs if total_pairs else None
        ),
        "step_technique_hit_fraction_of_evaluable_pairs": (
            pair_hits / evaluable_pairs if evaluable_pairs else None
        ),
        "fully_hit_step_fraction_of_evaluable_steps": (
            step_hits / evaluable_steps if evaluable_steps else None
        ),
        "claim_boundaries": {
            "event_level_recall": "NOT_CLAIMED",
            "event_level_precision": "NOT_CLAIMED",
            "false_positive_rate": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
        },
    }


__all__ = [
    "BrawlScoringError",
    "EXACT_TIME_TOLERANCE_SECONDS",
    "LEGACY_ATTACK_CROSSWALK",
    "event_bounds",
    "expected_technique_pairs",
    "expected_techniques",
    "finding_techniques",
    "hosts_equivalent",
    "normalize_host",
    "referenced_event_windows",
    "score_brawl_steps",
    "step_window",
    "technique_matches",
]
