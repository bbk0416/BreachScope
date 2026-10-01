#!/usr/bin/env python3
"""Disk-backed streaming scorer for the P2-37 DEDALE external baseline.

The reference evaluator loads the complete corpus and labels into Python memory.
This scorer preserves its event identity, Event conversion, rule engine,
confusion-matrix, technique, scenario, and per-source accounting contracts while
using SQLite for corpus/label/flag state and a second streaming corpus pass for
detection.

The full corpus order is preserved when passed to apply_rules(), so Windows
Security 4688 parent-PID linkage remains continuous across the corpus.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import evaluate_external_holdout as reference


class StreamingScoreError(RuntimeError):
    pass


def _require_p2_37_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("evaluation_class") != "external_baseline":
        raise StreamingScoreError(
            "P2-37 streaming scorer requires evaluation_class=external_baseline"
        )
    files = manifest.get("files") or []
    if not files:
        raise StreamingScoreError("manifest contains no corpus files")
    for row in files:
        if str(row.get("format") or "").casefold() != "jsonl":
            raise StreamingScoreError(
                "P2-37 streaming scorer supports JSONL corpus files only"
            )


def _prepare_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute(
        """
        CREATE TABLE labels (
            event_key TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            expected_techniques_json TEXT NOT NULL,
            notes TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE records (
            event_key TEXT PRIMARY KEY,
            source_file TEXT NOT NULL,
            record_index INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE flagged (
            event_key TEXT PRIMARY KEY
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE techniques (
            event_key TEXT NOT NULL,
            technique TEXT NOT NULL,
            PRIMARY KEY(event_key, technique)
        )
        """
    )
    conn.execute(
        "CREATE INDEX records_source_idx ON records(source_file)"
    )


def _load_labels(
    conn: sqlite3.Connection,
    path: Path,
    expected_sha256: str | None,
) -> Counter:
    if expected_sha256:
        actual = reference._sha256(path)
        if actual != expected_sha256.lower():
            raise reference.HoldoutError(
                "labels hash mismatch: "
                f"expected={expected_sha256.lower()} actual={actual}"
            )

    counts: Counter = Counter()
    for row in reference._iter_jsonl_dicts(path):
        key = str(row.get("event_key") or "").strip()
        label = str(row.get("label") or "").strip().lower()
        if not reference.re_full_sha256(key):
            raise reference.HoldoutError(
                "every label row needs a valid event_key"
            )
        if label not in reference.VALID_LABELS:
            raise reference.HoldoutError(
                f"invalid label {label!r} for event {key}"
            )
        techniques = row.get("expected_techniques") or []
        if not isinstance(techniques, list):
            raise reference.HoldoutError(
                "expected_techniques must be a list"
            )
        rendered = [str(x).upper() for x in techniques]
        try:
            conn.execute(
                """
                INSERT INTO labels(
                    event_key, label, expected_techniques_json, notes
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    key,
                    label,
                    json.dumps(rendered, ensure_ascii=False),
                    str(row.get("notes") or ""),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise reference.HoldoutError(
                f"duplicate label for event {key}"
            ) from exc
        counts[label] += 1
    return counts


def _iter_verified_raw(
    verified: list[dict[str, Any]],
) -> Iterable[tuple[str, int, dict[str, Any]]]:
    for row in verified:
        path = Path(row["_absolute_path"])
        source_name = str(row["path"])
        for record_index, raw in enumerate(
            reference._iter_jsonl_dicts(path),
            1,
        ):
            yield source_name, record_index, raw


def _index_corpus(
    conn: sqlite3.Connection,
    verified: list[dict[str, Any]],
) -> int:
    events = 0
    for source_name, record_index, raw in _iter_verified_raw(verified):
        key = reference.event_key(raw)
        prior = conn.execute(
            """
            SELECT source_file, record_index
            FROM records
            WHERE event_key = ?
            """,
            (key,),
        ).fetchone()
        if prior is not None:
            raise reference.HoldoutError(
                "duplicate event identity in holdout corpus: "
                f"{source_name}:{record_index} duplicates "
                f"{prior[0]}:{prior[1]}; "
                "the identity contract must be disambiguated before scoring"
            )
        conn.execute(
            """
            INSERT INTO records(event_key, source_file, record_index)
            VALUES (?, ?, ?)
            """,
            (key, source_name, record_index),
        )
        events += 1

    if events == 0:
        raise reference.HoldoutError(
            "holdout corpus contains zero events"
        )

    missing = int(
        conn.execute(
            """
            SELECT COUNT(*)
            FROM records r
            LEFT JOIN labels l ON l.event_key = r.event_key
            WHERE l.event_key IS NULL
            """
        ).fetchone()[0]
    )
    extra = int(
        conn.execute(
            """
            SELECT COUNT(*)
            FROM labels l
            LEFT JOIN records r ON r.event_key = l.event_key
            WHERE r.event_key IS NULL
            """
        ).fetchone()[0]
    )
    if missing or extra:
        raise reference.HoldoutError(
            f"label coverage must be exact: missing={missing} extra={extra}"
        )
    conn.commit()
    return events


def _event_stream(
    conn: sqlite3.Connection,
    verified: list[dict[str, Any]],
):
    for source_name, record_index, raw in _iter_verified_raw(verified):
        key = reference.event_key(raw)
        stored = conn.execute(
            """
            SELECT 1 FROM records
            WHERE event_key = ? AND source_file = ? AND record_index = ?
            """,
            (key, source_name, record_index),
        ).fetchone()
        if stored is None:
            raise StreamingScoreError(
                "streaming detection pass diverged from pre-detection "
                f"corpus index: {source_name}:{record_index}"
            )
        yield reference._record_to_event(raw)


def _per_source(
    conn: sqlite3.Connection,
) -> dict[str, dict[str, int]]:
    rows = conn.execute(
        """
        SELECT
            r.source_file,
            COUNT(*) AS events,
            SUM(CASE WHEN l.label = 'malicious' THEN 1 ELSE 0 END),
            SUM(CASE WHEN l.label = 'benign' THEN 1 ELSE 0 END),
            SUM(CASE WHEN l.label = 'ignore' THEN 1 ELSE 0 END),
            SUM(CASE WHEN l.label != 'ignore' THEN 1 ELSE 0 END),
            SUM(CASE WHEN f.event_key IS NOT NULL THEN 1 ELSE 0 END)
        FROM records r
        JOIN labels l ON l.event_key = r.event_key
        LEFT JOIN flagged f ON f.event_key = r.event_key
        GROUP BY r.source_file
        ORDER BY r.source_file
        """
    )
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        counts = {
            "events": int(row[1]),
            "malicious": int(row[2]),
            "benign": int(row[3]),
            "ignore": int(row[4]),
            "scored": int(row[5]),
            "flagged": int(row[6]),
        }
        out[str(row[0])] = {
            key: value
            for key, value in counts.items()
            if value
        }
    return out


def _technique_accounting(
    conn: sqlite3.Connection,
) -> tuple[int, int]:
    total = 0
    hits = 0
    rows = conn.execute(
        """
        SELECT l.event_key, l.expected_techniques_json
        FROM labels l
        JOIN records r ON r.event_key = l.event_key
        WHERE l.label != 'ignore'
          AND l.expected_techniques_json != '[]'
        """
    )
    for event_key, raw_expected in rows:
        expected = set(json.loads(str(raw_expected)))
        observed = {
            str(row[0])
            for row in conn.execute(
                "SELECT technique FROM techniques WHERE event_key = ?",
                (event_key,),
            )
        }
        total += len(expected)
        hits += sum(
            any(
                reference._attack_requirement_satisfied(
                    required,
                    technique,
                )
                for technique in observed
            )
            for required in expected
        )
    return hits, total


def _scenario_outcomes(
    manifest: dict[str, Any],
    conn: sqlite3.Connection,
) -> dict[str, Any]:
    outcomes = []
    for scenario in manifest.get("scenarios") or []:
        scenario_id = str(scenario["scenario_id"])
        source_files = sorted(
            {str(x) for x in scenario["source_files"]}
        )
        expected = {
            str(x).upper()
            for x in scenario["expected_techniques"]
        }
        placeholders = ",".join("?" for _ in source_files)
        event_count = int(
            conn.execute(
                f"""
                SELECT COUNT(*)
                FROM records
                WHERE source_file IN ({placeholders})
                """,
                tuple(source_files),
            ).fetchone()[0]
        )
        observed = {
            str(row[0])
            for row in conn.execute(
                f"""
                SELECT DISTINCT t.technique
                FROM techniques t
                JOIN records r ON r.event_key = t.event_key
                WHERE r.source_file IN ({placeholders})
                """,
                tuple(source_files),
            )
        }
        matched = {
            required
            for required in expected
            if any(
                reference._attack_requirement_satisfied(
                    required,
                    technique,
                )
                for technique in observed
            )
        }
        missing = expected - matched
        outcomes.append(
            {
                "scenario_id": scenario_id,
                "source_files": source_files,
                "event_count": event_count,
                "expected_techniques": sorted(expected),
                "observed_techniques": sorted(observed),
                "matched_techniques": sorted(matched),
                "missing_techniques": sorted(missing),
                "technique_recall": reference._safe_div(
                    len(matched),
                    len(expected),
                ),
                "status": "hit" if not missing else "miss",
            }
        )
    hits = sum(row["status"] == "hit" for row in outcomes)
    misses = sum(row["status"] == "miss" for row in outcomes)
    return {
        "total": len(outcomes),
        "hits": hits,
        "misses": misses,
        "hit_rate": reference._safe_div(hits, len(outcomes)),
        "outcomes": outcomes,
    }


def score_streaming(
    *,
    repo: Path,
    manifest_path: Path,
    corpus_root: Path,
    labels_path: Path,
    freeze_path: Path,
    rules_dir: Path,
    work_dir: Path,
) -> dict[str, Any]:
    manifest = reference.load_manifest(manifest_path)
    _require_p2_37_manifest(manifest)

    labels_cfg = manifest.get("labels") or {}
    if not isinstance(labels_cfg, dict):
        raise reference.HoldoutError(
            "manifest labels section must be a mapping"
        )
    expected_labels_hash = (
        str(labels_cfg.get("sha256") or "").strip().lower() or None
    )
    if (
        expected_labels_hash
        and not reference.re_full_sha256(expected_labels_hash)
    ):
        raise reference.HoldoutError(
            "manifest labels.sha256 must be a SHA-256 hex digest"
        )

    freeze = reference._verify_freeze(
        repo.resolve(),
        rules_dir.resolve(),
        freeze_path.resolve(),
    )
    verified = reference.verify_corpus(manifest, corpus_root)
    for row in verified:
        if str(row.get("format") or "").casefold() != "jsonl":
            raise StreamingScoreError(
                "P2-37 streaming scorer supports JSONL corpus files only"
            )

    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="p2-37-stream-score-",
        dir=str(work_dir),
    ) as temp_dir:
        conn = sqlite3.connect(Path(temp_dir) / "state.sqlite3")
        try:
            _prepare_db(conn)
            label_counts = _load_labels(
                conn,
                labels_path.resolve(),
                expected_labels_hash,
            )
            events_count = _index_corpus(conn, verified)

            # Detection is imported and run only after exact label coverage.
            from breachscope.analyzer import apply_rules
            from breachscope.rules import load_rules

            rules = load_rules(rules_dir.resolve())
            findings = 0
            unknown_finding_events = 0

            tracemalloc.start()
            started = time.perf_counter()
            for finding in apply_rules(
                _event_stream(conn, verified),
                rules,
            ):
                findings += 1
                event = getattr(finding, "event", None)
                if event is None:
                    unknown_finding_events += 1
                    continue
                key = reference.event_key(event)
                row = conn.execute(
                    "SELECT 1 FROM records WHERE event_key = ?",
                    (key,),
                ).fetchone()
                if row is None:
                    unknown_finding_events += 1
                    continue

                conn.execute(
                    "INSERT OR IGNORE INTO flagged(event_key) VALUES (?)",
                    (key,),
                )
                for technique in reference._finding_techniques(finding):
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO techniques(event_key, technique)
                        VALUES (?, ?)
                        """,
                        (key, technique),
                    )

            runtime_seconds = time.perf_counter() - started
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            conn.commit()

            if unknown_finding_events:
                raise reference.HoldoutError(
                    f"{unknown_finding_events} finding(s) could not be "
                    "mapped back to holdout events"
                )

            flagged_events = int(
                conn.execute(
                    "SELECT COUNT(*) FROM flagged"
                ).fetchone()[0]
            )
            flagged_ignored = int(
                conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM flagged f
                    JOIN labels l ON l.event_key = f.event_key
                    WHERE l.label = 'ignore'
                    """
                ).fetchone()[0]
            )
            tp = int(
                conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM flagged f
                    JOIN labels l ON l.event_key = f.event_key
                    WHERE l.label = 'malicious'
                    """
                ).fetchone()[0]
            )
            fp = int(
                conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM flagged f
                    JOIN labels l ON l.event_key = f.event_key
                    WHERE l.label = 'benign'
                    """
                ).fetchone()[0]
            )
            malicious = int(label_counts["malicious"])
            benign = int(label_counts["benign"])
            ignored = int(label_counts["ignore"])
            confusion = {
                "tp": tp,
                "fp": fp,
                "tn": benign - fp,
                "fn": malicious - tp,
            }
            expected_hits, expected_total = _technique_accounting(
                conn
            )
            scenarios = _scenario_outcomes(manifest, conn)
            per_source = _per_source(conn)
        finally:
            conn.close()

    return {
        "schema": reference.RESULT_SCHEMA,
        "kind": "external_holdout_measurement",
        "claim_boundary": {
            "production_detection_quality_certified": False,
            "independent_provenance_proven_by_tool": False,
            "ground_truth_quality_proven_by_tool": False,
            "evaluation_class": manifest["evaluation_class"],
            "manifest_declares_final_blind": False,
            "note": (
                "Hashes and protocol self-attestations were enforced. "
                "External provenance, label quality, and representativeness "
                "require independent evidence."
            ),
        },
        "freeze": freeze,
        "corpus": {
            "manifest_sha256": reference._sha256(manifest_path),
            "labels_sha256": reference._sha256(labels_path),
            "events": events_count,
            "scored_events": malicious + benign,
            "ignored_events": ignored,
            "malicious": malicious,
            "benign": benign,
            "source_files": len(manifest["files"]),
        },
        "detection": {
            "rules": len(rules),
            "findings": findings,
            "flagged_events": flagged_events,
            "flagged_ignored_events": flagged_ignored,
            "confusion": confusion,
            "precision": reference._safe_div(
                confusion["tp"],
                confusion["tp"] + confusion["fp"],
            ),
            "recall": reference._safe_div(
                confusion["tp"],
                confusion["tp"] + confusion["fn"],
            ),
            "false_positive_rate": reference._safe_div(
                confusion["fp"],
                confusion["fp"] + confusion["tn"],
            ),
            "expected_technique_hits": expected_hits,
            "expected_technique_total": expected_total,
            "expected_technique_recall": reference._safe_div(
                expected_hits,
                expected_total,
            ),
        },
        "scenarios": scenarios,
        "performance": {
            "runtime_seconds": runtime_seconds,
            "peak_memory_mb": peak_bytes / (1024 * 1024),
            "measurement_note": (
                "Streaming runtime includes on-demand Event materialization "
                "during apply_rules; it is not directly comparable to the "
                "reference evaluator's pre-materialized-event runtime."
            ),
        },
        "per_source": per_source,
        "streaming_execution": {
            "corpus_loaded_fully_into_python_memory": False,
            "labels_loaded_fully_into_python_memory": False,
            "disk_backed_state": "SQLite",
            "corpus_passes": 2,
            "detection_event_order_preserved": True,
        },
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Disk-backed streaming P2-37 external-baseline scorer."
    )
    ap.add_argument("--repo", default=".")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--corpus-root", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--freeze", required=True)
    ap.add_argument("--rules-dir", default="rules")
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--out", required=True)
    return ap


def main() -> int:
    args = parser().parse_args()
    try:
        result = score_streaming(
            repo=Path(args.repo),
            manifest_path=Path(args.manifest),
            corpus_root=Path(args.corpus_root),
            labels_path=Path(args.labels),
            freeze_path=Path(args.freeze),
            rules_dir=Path(args.rules_dir),
            work_dir=Path(args.work_dir),
        )
    except (reference.HoldoutError, StreamingScoreError) as exc:
        print(f"HOLDOUT ERROR: {exc}", file=__import__("sys").stderr)
        return 2

    text = json.dumps(result, indent=2, ensure_ascii=False)
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        print(
            f"HOLDOUT ERROR: refusing to overwrite existing result: {out}",
            file=__import__("sys").stderr,
        )
        return 2
    out.write_text(text, encoding="utf-8", newline="\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
