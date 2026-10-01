#!/usr/bin/env python3
"""Streaming external-holdout indexer for P2-37.

Produces the same JSONL index bytes as evaluate_external_holdout.py index for
JSONL corpus files, but never retains the full corpus in Python memory.
Detection rules and provider labels are not read or executed.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import evaluate_external_holdout as reference


class StreamingIndexError(RuntimeError):
    pass


def _safe_verified_files(
    manifest: dict[str, Any],
    corpus_root: Path,
) -> list[dict[str, Any]]:
    verified = reference.verify_corpus(manifest, corpus_root)
    for row in verified:
        if str(row.get("format") or "").casefold() != "jsonl":
            raise StreamingIndexError(
                "P2-37 streaming indexer supports JSONL corpus files only"
            )
    return verified


def build_streaming_index(
    *,
    manifest_path: Path,
    corpus_root: Path,
    out: Path,
) -> dict[str, Any]:
    manifest = reference.load_manifest(manifest_path)
    verified = _safe_verified_files(manifest, corpus_root)

    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        raise StreamingIndexError(f"refusing to overwrite existing index: {out}")

    tmp_out = out.with_suffix(out.suffix + ".tmp")
    tmp_out.unlink(missing_ok=True)
    events = 0
    source_files = 0

    try:
        with tempfile.TemporaryDirectory(
            prefix="p2-37-index-",
            dir=str(out.parent),
        ) as temp_dir:
            db_path = Path(temp_dir) / "seen.sqlite3"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("PRAGMA journal_mode=OFF")
                conn.execute("PRAGMA synchronous=OFF")
                conn.execute("PRAGMA temp_store=FILE")
                conn.execute(
                    """
                    CREATE TABLE seen (
                        event_key TEXT PRIMARY KEY,
                        source_file TEXT NOT NULL,
                        record_index INTEGER NOT NULL
                    )
                    """
                )

                with tmp_out.open("w", encoding="utf-8", newline="\n") as handle:
                    for file_row in verified:
                        source_files += 1
                        path = Path(file_row["_absolute_path"])
                        source_name = str(file_row["path"])
                        for record_index, raw in enumerate(
                            reference._iter_jsonl_dicts(path),
                            1,
                        ):
                            key = reference.event_key(raw)
                            prior = conn.execute(
                                """
                                SELECT source_file, record_index
                                FROM seen
                                WHERE event_key = ?
                                """,
                                (key,),
                            ).fetchone()
                            if prior is not None:
                                raise reference.HoldoutError(
                                    "duplicate event identity in holdout corpus: "
                                    f"{source_name}:{record_index} duplicates "
                                    f"{prior[0]}:{prior[1]}; "
                                    "the identity contract must be disambiguated "
                                    "before scoring"
                                )
                            conn.execute(
                                """
                                INSERT INTO seen(event_key, source_file, record_index)
                                VALUES (?, ?, ?)
                                """,
                                (key, source_name, record_index),
                            )

                            public = {
                                "event_key": key,
                                "source_file": source_name,
                                "record_index": record_index,
                                "identity": reference.event_identity_payload(raw),
                                "label": "",
                                "allowed_labels": [
                                    "malicious",
                                    "benign",
                                    "ignore",
                                ],
                                "expected_techniques": [],
                                "notes": "",
                            }
                            handle.write(
                                json.dumps(public, ensure_ascii=False) + "\n"
                            )
                            events += 1
                conn.commit()
            finally:
                conn.close()

        if events == 0:
            raise reference.HoldoutError(
                "holdout corpus contains zero events"
            )
        os.replace(tmp_out, out)
    except Exception:
        tmp_out.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
        raise

    return {
        "status": "PASS",
        "events": events,
        "source_files": source_files,
        "index_sha256": reference._sha256(out),
        "detection_rules_executed": False,
        "findings_emitted": False,
        "labels_read": False,
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "Build a byte-identical external-holdout labeling index without "
            "loading the full JSONL corpus into memory."
        )
    )
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--corpus-root", required=True)
    ap.add_argument("--out", required=True)
    return ap


def main() -> int:
    args = parser().parse_args()
    try:
        result = build_streaming_index(
            manifest_path=Path(args.manifest),
            corpus_root=Path(args.corpus_root),
            out=Path(args.out),
        )
    except (reference.HoldoutError, StreamingIndexError) as exc:
        print(f"HOLDOUT ERROR: {exc}", file=__import__("sys").stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
