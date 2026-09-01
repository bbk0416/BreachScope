from __future__ import annotations

import argparse
import inspect
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _normalize_techniques(value: Any) -> set[str]:
    if value is None:
        return set()

    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = [str(value)]

    result: set[str] = set()
    for item in items:
        text = str(item).strip().upper()
        if not text:
            continue

        # Accept comma/space separated metadata without silently inventing IDs.
        for token in text.replace(",", " ").split():
            token = token.strip()
            if token.startswith("ATTACK."):
                token = token[7:]
            if token.startswith("T") and token[1:2].isdigit():
                result.add(token)

    return result


def _construct_event(Event, payload: dict[str, Any]):
    signature = inspect.signature(Event)
    kwargs = {
        name: payload[name]
        for name in signature.parameters
        if name in payload
    }
    return Event(**kwargs)


def _call_load_rules(load_rules, rules_dir: Path):
    params = inspect.signature(load_rules).parameters
    attempts = []

    if "rules_dir" in params:
        attempts.append(lambda: load_rules(rules_dir=rules_dir))
    if "path" in params:
        attempts.append(lambda: load_rules(path=rules_dir))

    attempts.extend(
        [
            lambda: load_rules(rules_dir),
            lambda: load_rules(str(rules_dir)),
        ]
    )

    last = None
    for attempt in attempts:
        try:
            return list(attempt())
        except Exception as exc:
            last = exc

    raise RuntimeError(
        f"Could not load native rules from {rules_dir}: {last}"
    )


def _read_manifest(path: Path) -> dict[str, Any]:
    suffix = path.suffix.casefold()
    text = path.read_text(encoding="utf-8-sig")

    if suffix == ".json":
        data = json.loads(text)
    elif suffix in {".yaml", ".yml"}:
        import yaml
        data = yaml.safe_load(text)
    else:
        raise ValueError(
            f"Unsupported evaluation manifest extension: {path.suffix}"
        )

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain an object/map")
    return data


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_no, raw in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(),
        1,
    ):
        text = raw.strip()
        if not text:
            continue

        try:
            item = json.loads(text)
        except Exception as exc:
            raise ValueError(
                f"{path}:{line_no}: invalid JSONL: {exc}"
            ) from exc

        if not isinstance(item, dict):
            raise ValueError(
                f"{path}:{line_no}: each JSONL row must be an object"
            )

        rows.append(item)

    return rows


def _metric(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 1.0
    return numerator / denominator


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except Exception:
        return path.as_posix()


def evaluate(
    manifest_path: Path,
    *,
    rules_dir: Path | None = None,
) -> dict[str, Any]:
    from breachscope.analyzer import apply_rules
    from breachscope.rules import load_rules
    from breachscope.schemas import Event

    manifest_path = manifest_path.resolve()
    manifest = _read_manifest(manifest_path)

    schema_version = str(manifest.get("schema_version", "")).strip()
    if schema_version != "1":
        raise ValueError(
            f"Unsupported evaluation manifest schema_version={schema_version!r}"
        )

    corpora = manifest.get("corpora")
    if not isinstance(corpora, list) or not corpora:
        raise ValueError("Evaluation manifest requires non-empty corpora")

    thresholds = manifest.get("thresholds") or {}
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be an object")

    min_precision = float(thresholds.get("min_precision", 0.95))
    min_recall = float(thresholds.get("min_recall", 0.90))
    min_malicious_events = int(
        thresholds.get("min_malicious_events", 1)
    )
    min_benign_events = int(
        thresholds.get("min_benign_events", 1)
    )

    active_rules_dir = (
        rules_dir.resolve()
        if rules_dir is not None
        else REPO_ROOT / "rules"
    )
    rules = _call_load_rules(load_rules, active_rules_dir)
    if not rules:
        raise RuntimeError("Native rulepack loaded zero rules")

    tp = fp = tn = fn = 0
    malicious_events = benign_events = 0
    total_findings = 0

    false_positive_events: list[dict[str, Any]] = []
    false_negative_events: list[dict[str, Any]] = []
    per_corpus: dict[str, Any] = {}

    aggregate_detected_rules = Counter()
    aggregate_detected_techniques = Counter()

    for entry in corpora:
        if not isinstance(entry, dict):
            raise ValueError("Each corpora entry must be an object")

        corpus_id = str(entry.get("id", "")).strip()
        classification = str(
            entry.get("classification", "")
        ).strip().lower()
        events_file = str(entry.get("events_file", "")).strip()

        if not corpus_id:
            raise ValueError("Corpus entry missing id")
        if classification not in {"benign", "malicious"}:
            raise ValueError(
                f"{corpus_id}: classification must be benign or malicious"
            )
        if not events_file:
            raise ValueError(f"{corpus_id}: missing events_file")

        events_path = (REPO_ROOT / events_file).resolve()
        try:
            events_path.relative_to(REPO_ROOT)
        except ValueError as exc:
            raise ValueError(
                f"{corpus_id}: events_file escapes repository root"
            ) from exc

        if not events_path.exists():
            raise FileNotFoundError(events_path)

        payloads = _read_jsonl(events_path)
        corpus_findings = 0
        corpus_positive_events = 0
        corpus_rule_counts = Counter()
        corpus_detected_techniques: set[str] = set()
        corpus_expected_techniques: set[str] = set()

        expected_field = str(
            entry.get(
                "expected_techniques_field",
                "sample_expected_techniques",
            )
        ).strip()

        for event_index, payload in enumerate(payloads):
            event = _construct_event(Event, payload)
            findings = list(apply_rules([event], rules))
            predicted_positive = bool(findings)

            detected_rules = {
                str(getattr(f, "rule_id", "")).strip()
                for f in findings
                if str(getattr(f, "rule_id", "")).strip()
            }
            detected_techniques = set()
            for finding in findings:
                detected_techniques.update(
                    _normalize_techniques(
                        getattr(finding, "mitre_technique", "")
                    )
                )

            total_findings += len(findings)
            corpus_findings += len(findings)
            corpus_rule_counts.update(detected_rules)
            aggregate_detected_rules.update(detected_rules)
            aggregate_detected_techniques.update(detected_techniques)
            corpus_detected_techniques.update(detected_techniques)

            if predicted_positive:
                corpus_positive_events += 1

            if classification == "malicious":
                malicious_events += 1
                expected = _normalize_techniques(
                    payload.get(expected_field)
                )
                if not expected:
                    raise ValueError(
                        f"{corpus_id}[{event_index}] is malicious but "
                        f"{expected_field!r} has no ATT&CK technique"
                    )
                corpus_expected_techniques.update(expected)

                if predicted_positive:
                    tp += 1
                else:
                    fn += 1
                    false_negative_events.append(
                        {
                            "corpus_id": corpus_id,
                            "event_index": event_index,
                            "host": str(payload.get("host", "")),
                            "command_line": str(
                                payload.get("command_line", "")
                            ),
                            "expected_techniques": sorted(expected),
                        }
                    )
            else:
                benign_events += 1
                if predicted_positive:
                    fp += 1
                    false_positive_events.append(
                        {
                            "corpus_id": corpus_id,
                            "event_index": event_index,
                            "host": str(payload.get("host", "")),
                            "command_line": str(
                                payload.get("command_line", "")
                            ),
                            "rule_ids": sorted(detected_rules),
                            "techniques": sorted(detected_techniques),
                        }
                    )
                else:
                    tn += 1

        technique_recall = None
        missing_techniques: list[str] = []
        if classification == "malicious":
            missing_techniques = sorted(
                corpus_expected_techniques
                - corpus_detected_techniques
            )
            technique_recall = _metric(
                len(
                    corpus_expected_techniques
                    & corpus_detected_techniques
                ),
                len(corpus_expected_techniques),
            )

        per_corpus[corpus_id] = {
            "classification": classification,
            "events_file": _relative(events_path),
            "events": len(payloads),
            "positive_events": corpus_positive_events,
            "findings": corpus_findings,
            "rule_counts": dict(
                sorted(corpus_rule_counts.items())
            ),
            "expected_techniques": sorted(
                corpus_expected_techniques
            ),
            "detected_techniques": sorted(
                corpus_detected_techniques
            ),
            "technique_recall": technique_recall,
            "missing_techniques": missing_techniques,
        }

    precision = _metric(tp, tp + fp)
    recall = _metric(tp, tp + fn)

    checks = {
        "minimum_malicious_events": (
            malicious_events >= min_malicious_events
        ),
        "minimum_benign_events": (
            benign_events >= min_benign_events
        ),
        "precision": precision >= min_precision,
        "recall": recall >= min_recall,
    }

    passed = all(checks.values())

    return {
        "schema_version": "1",
        "evaluation_kind": "curated_regression_corpus",
        "passed": passed,
        "rules": len(rules),
        "manifest": _relative(manifest_path),
        "thresholds": {
            "min_precision": min_precision,
            "min_recall": min_recall,
            "min_malicious_events": min_malicious_events,
            "min_benign_events": min_benign_events,
        },
        "counts": {
            "malicious_events": malicious_events,
            "benign_events": benign_events,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "findings": total_findings,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
        },
        "checks": checks,
        "false_positive_events": false_positive_events,
        "false_negative_events": false_negative_events,
        "detected_rule_counts": dict(
            aggregate_detected_rules.most_common()
        ),
        "detected_technique_counts": dict(
            aggregate_detected_techniques.most_common()
        ),
        "corpora": per_corpus,
        "limitations": [
            "Synthetic curated regression corpus only.",
            "Does not estimate production-world precision or recall.",
            "Does not replace real EVTX validation or organization-specific benign baselines.",
        ],
    }


def _print_human(result: dict[str, Any]) -> None:
    counts = result["counts"]
    metrics = result["metrics"]
    thresholds = result["thresholds"]

    print("BreachScope curated detection evaluation")
    print("kind:", result["evaluation_kind"])
    print("rules:", result["rules"])
    print(
        "events:",
        counts["malicious_events"],
        "malicious +",
        counts["benign_events"],
        "benign",
    )
    print(
        "confusion:",
        f"TP={counts['tp']}",
        f"FP={counts['fp']}",
        f"TN={counts['tn']}",
        f"FN={counts['fn']}",
    )
    print(
        "precision:",
        f"{metrics['precision']:.4f}",
        f"(gate >= {thresholds['min_precision']:.4f})",
    )
    print(
        "recall:",
        f"{metrics['recall']:.4f}",
        f"(gate >= {thresholds['min_recall']:.4f})",
    )
    print("findings:", counts["findings"])

    if result["false_positive_events"]:
        print("\nFalse-positive events:")
        for item in result["false_positive_events"]:
            print(
                f"  {item['corpus_id']}[{item['event_index']}] "
                f"rules={','.join(item['rule_ids'])} "
                f"cmd={item['command_line']}"
            )

    if result["false_negative_events"]:
        print("\nFalse-negative events:")
        for item in result["false_negative_events"]:
            print(
                f"  {item['corpus_id']}[{item['event_index']}] "
                f"expected={','.join(item['expected_techniques'])} "
                f"cmd={item['command_line']}"
            )

    print("\nPer-corpus technique coverage (diagnostic, not gate):")
    for corpus_id, data in result["corpora"].items():
        if data["classification"] != "malicious":
            continue
        value = data["technique_recall"]
        print(
            f"  {corpus_id}: "
            f"{value:.4f}" if value is not None
            else f"  {corpus_id}: n/a"
        )
        if data["missing_techniques"]:
            print(
                "    missing:",
                ", ".join(data["missing_techniques"]),
            )

    print("\nPASS" if result["passed"] else "\nFAIL")
    print(
        "NOTE: This is a curated synthetic regression metric, "
        "not a production detection-quality claim."
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPO_ROOT
        / "samples"
        / "evaluation"
        / "ground_truth.yaml",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=REPO_ROOT / "rules",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    args = parser.parse_args()

    result = evaluate(
        args.manifest,
        rules_dir=args.rules_dir,
    )

    if args.json:
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        _print_human(result)

    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
