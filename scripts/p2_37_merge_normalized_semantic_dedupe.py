#!/usr/bin/env python3
"""Resumable semantic-deduplicating final merge for P2-37.

This tool consumes only committed P2-37 normalization member checkpoints.
A duplicate provider identity is accepted only when the canonical normalized
corpus row bytes are exactly identical. In that case the first occurrence in
canonical member/source-line order is retained and later copies are skipped.
If the normalized bytes differ, the merge aborts before labels or detection.

Provider labels are never read and detection is never executed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
EXPECTED_AUTHORITY_GIT_BLOB_SHA1 = "60962c1c3e3b28de0667445c175d4b7d4200bbe4"
STATE_SCHEMA = "breachscope.p2_37_semantic_dedupe_merge_state.v1"
DUPLICATE_POLICY = "KEEP_FIRST_IF_NORMALIZED_BYTES_EXACTLY_IDENTICAL_ELSE_ABORT"


class SemanticDedupeMergeError(RuntimeError):
    pass


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SemanticDedupeMergeError(f"unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _new_state(
    *,
    work_dir: Path,
    adapter_path: Path,
    authority_path: Path,
    start: str,
    end: str,
    expected_members: int,
    out_corpus: Path,
    out_identity: Path,
) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "duplicate_policy": DUPLICATE_POLICY,
        "work_dir": str(work_dir.resolve()),
        "adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
        "adapter_path": str(adapter_path.resolve()),
        "authority_git_blob_sha1": EXPECTED_AUTHORITY_GIT_BLOB_SHA1,
        "authority_path": str(authority_path.resolve()),
        "start": start,
        "end": end,
        "expected_members": expected_members,
        "out_corpus": str(out_corpus.resolve()),
        "out_identity": str(out_identity.resolve()),
        "next_index": 0,
        "corpus_committed_size": 0,
        "identity_committed_size": 0,
        "record_index": 0,
        "seen_count": 0,
        "source_rows": 0,
        "outside_window_rows": 0,
        "input_selected_rows": 0,
        "selected_rows": 0,
        "duplicate_rows": 0,
        "selected_source_files": 0,
        "complete": False,
    }


def _validate_state(
    state: dict[str, Any],
    *,
    work_dir: Path,
    adapter_path: Path,
    authority_path: Path,
    start: str,
    end: str,
    expected_members: int,
    out_corpus: Path,
    out_identity: Path,
) -> None:
    expected = _new_state(
        work_dir=work_dir,
        adapter_path=adapter_path,
        authority_path=authority_path,
        start=start,
        end=end,
        expected_members=expected_members,
        out_corpus=out_corpus,
        out_identity=out_identity,
    )
    for key in (
        "schema",
        "duplicate_policy",
        "work_dir",
        "adapter_git_blob_sha1",
        "adapter_path",
        "authority_git_blob_sha1",
        "authority_path",
        "start",
        "end",
        "expected_members",
        "out_corpus",
        "out_identity",
    ):
        if state.get(key) != expected[key]:
            raise SemanticDedupeMergeError(
                f"merge state contract mismatch: {key}: "
                f"{state.get(key)!r} != {expected[key]!r}"
            )


def _open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen (
            provider_identity TEXT PRIMARY KEY,
            corpus_row_sha256 TEXT NOT NULL,
            member_index INTEGER NOT NULL
        )
        """
    )
    columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(seen)")
    }
    if columns != {
        "provider_identity",
        "corpus_row_sha256",
        "member_index",
    }:
        raise SemanticDedupeMergeError(
            f"unexpected seen schema: {sorted(columns)}"
        )
    conn.commit()
    return conn


def _recover(
    *,
    state: dict[str, Any],
    corpus_partial: Path,
    identity_partial: Path,
    conn: sqlite3.Connection,
    current_corpus_temp: Path,
    current_identity_temp: Path,
) -> None:
    next_index = int(state["next_index"])
    for path, committed in (
        (corpus_partial, int(state["corpus_committed_size"])),
        (identity_partial, int(state["identity_committed_size"])),
    ):
        if not path.exists():
            if committed:
                raise SemanticDedupeMergeError(
                    f"partial output missing below committed size: {path}"
                )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        actual = path.stat().st_size
        if actual < committed:
            raise SemanticDedupeMergeError(
                f"partial output shorter than committed size: "
                f"{path.name}: {actual} < {committed}"
            )
        if actual > committed:
            with path.open("r+b") as handle:
                handle.truncate(committed)
                handle.flush()
                os.fsync(handle.fileno())

    current_corpus_temp.unlink(missing_ok=True)
    current_identity_temp.unlink(missing_ok=True)
    conn.execute(
        "DELETE FROM seen WHERE member_index >= ?",
        (next_index,),
    )
    conn.commit()
    seen_count = int(
        conn.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
    )
    if seen_count != int(state["seen_count"]):
        raise SemanticDedupeMergeError(
            f"SQLite seen count mismatch after recovery: "
            f"{seen_count} != {state['seen_count']}"
        )


def _append_temp(*, temp: Path, partial: Path) -> int:
    written = 0
    with temp.open("rb") as src, partial.open("ab") as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            dst.write(chunk)
            written += len(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    return written


def _process_batch(
    *,
    batch: list[tuple[str, str, bytes, dict[str, Any]]],
    conn: sqlite3.Connection,
    member_index: int,
    corpus_out,
    identity_out,
    authority,
    adapter,
    json_backend: str,
    orjson_module,
    next_record: int,
) -> tuple[int, int, int]:
    if not batch:
        return next_record, 0, 0

    params = [
        (provider_id, corpus_sha, member_index)
        for provider_id, corpus_sha, _, _ in batch
    ]
    inserted = 0
    duplicates = 0

    conn.execute("SAVEPOINT p2_37_batch")
    try:
        conn.executemany(
            """
            INSERT INTO seen(
                provider_identity,
                corpus_row_sha256,
                member_index
            )
            VALUES (?, ?, ?)
            """,
            params,
        )
        conn.execute("RELEASE p2_37_batch")
        decisions = [True] * len(batch)
    except sqlite3.IntegrityError:
        conn.execute("ROLLBACK TO p2_37_batch")
        conn.execute("RELEASE p2_37_batch")
        decisions: list[bool] = []
        for provider_id, corpus_sha, _, _ in batch:
            try:
                conn.execute(
                    """
                    INSERT INTO seen(
                        provider_identity,
                        corpus_row_sha256,
                        member_index
                    )
                    VALUES (?, ?, ?)
                    """,
                    (provider_id, corpus_sha, member_index),
                )
                decisions.append(True)
            except sqlite3.IntegrityError as exc:
                prior = conn.execute(
                    """
                    SELECT corpus_row_sha256, member_index
                    FROM seen
                    WHERE provider_identity = ?
                    """,
                    (provider_id,),
                ).fetchone()
                if prior is None:
                    raise SemanticDedupeMergeError(
                        "duplicate provider identity was not recoverable "
                        f"from seen table: {provider_id}"
                    ) from exc
                if str(prior[0]) != corpus_sha:
                    raise SemanticDedupeMergeError(
                        "provider identity collision has different normalized "
                        f"bytes: {provider_id}; first_member={prior[1]}; "
                        f"current_member={member_index}"
                    ) from exc
                decisions.append(False)

    for keep, (provider_id, _, corpus_raw, identity_row) in zip(
        decisions,
        batch,
    ):
        if not keep:
            duplicates += 1
            continue
        inserted += 1
        next_record += 1
        corpus_out.write(corpus_raw)
        identity_out.write(
            authority._identity_output_bytes(
                {
                    "record_index": next_record,
                    "provider_identity": provider_id,
                    "source_file": str(identity_row["source_file"]),
                    "source_line": int(identity_row["source_line"]),
                    "source_row_sha256": str(
                        identity_row["source_row_sha256"]
                    ),
                },
                backend=json_backend,
                orjson_module=orjson_module,
                adapter=adapter,
            )
        )

    return next_record, inserted, duplicates


def _transform_member_validated(
    *,
    corpus_source: Path,
    identity_source: Path,
    marker: dict[str, Any],
    corpus_temp: Path,
    identity_temp: Path,
    adapter,
    authority,
    conn: sqlite3.Connection,
    start_record_index: int,
    json_backend: str,
    orjson_module,
    batch_size: int,
) -> dict[str, int]:
    if batch_size < 1:
        raise SemanticDedupeMergeError("batch_size must be >= 1")

    expected_corpus_size = int(marker["corpus_size_bytes"])
    expected_identity_size = int(marker["identity_size_bytes"])
    expected_rows = int(marker["selected_rows"])

    corpus_h = hashlib.sha256()
    identity_h = hashlib.sha256()
    corpus_input_size = 0
    identity_input_size = 0
    input_rows = 0
    kept_rows = 0
    duplicate_rows = 0
    next_record = start_record_index
    batch: list[tuple[str, str, bytes, dict[str, Any]]] = []

    conn.execute("BEGIN IMMEDIATE")
    try:
        with (
            corpus_source.open("rb") as corpus_in,
            identity_source.open("rb") as identity_in,
            corpus_temp.open("wb") as corpus_out,
            identity_temp.open("wb") as identity_out,
        ):
            pairs = itertools.zip_longest(
                corpus_in,
                identity_in,
                fillvalue=None,
            )
            for corpus_raw, identity_raw in pairs:
                if corpus_raw is None or identity_raw is None:
                    raise SemanticDedupeMergeError(
                        f"corpus/identity row count mismatch "
                        f"index={marker['index']}"
                    )
                corpus_h.update(corpus_raw)
                identity_h.update(identity_raw)
                corpus_input_size += len(corpus_raw)
                identity_input_size += len(identity_raw)

                corpus_text = corpus_raw.strip()
                identity_text = identity_raw.strip()
                if not corpus_text or not identity_text:
                    raise SemanticDedupeMergeError(
                        f"blank canonical row index={marker['index']} "
                        f"row={input_rows + 1}"
                    )

                identity_row = authority._decode_identity_json(
                    identity_text,
                    backend=json_backend,
                    orjson_module=orjson_module,
                )
                provider_id = str(identity_row["provider_identity"])
                corpus_sha = hashlib.sha256(corpus_raw).hexdigest()
                batch.append(
                    (
                        provider_id,
                        corpus_sha,
                        corpus_raw,
                        {
                            "source_file": str(marker["source_name"]),
                            "source_line": int(identity_row["source_line"]),
                            "source_row_sha256": str(
                                identity_row["source_row_sha256"]
                            ),
                        },
                    )
                )
                input_rows += 1

                if len(batch) >= batch_size:
                    next_record, inserted, duplicates = _process_batch(
                        batch=batch,
                        conn=conn,
                        member_index=int(marker["index"]),
                        corpus_out=corpus_out,
                        identity_out=identity_out,
                        authority=authority,
                        adapter=adapter,
                        json_backend=json_backend,
                        orjson_module=orjson_module,
                        next_record=next_record,
                    )
                    kept_rows += inserted
                    duplicate_rows += duplicates
                    batch.clear()

            if batch:
                next_record, inserted, duplicates = _process_batch(
                    batch=batch,
                    conn=conn,
                    member_index=int(marker["index"]),
                    corpus_out=corpus_out,
                    identity_out=identity_out,
                    authority=authority,
                    adapter=adapter,
                    json_backend=json_backend,
                    orjson_module=orjson_module,
                    next_record=next_record,
                )
                kept_rows += inserted
                duplicate_rows += duplicates
                batch.clear()

            corpus_out.flush()
            identity_out.flush()
            os.fsync(corpus_out.fileno())
            os.fsync(identity_out.fileno())

        if corpus_input_size != expected_corpus_size:
            raise SemanticDedupeMergeError(
                f"corpus chunk size mismatch index={marker['index']}: "
                f"{corpus_input_size} != {expected_corpus_size}"
            )
        if identity_input_size != expected_identity_size:
            raise SemanticDedupeMergeError(
                f"identity chunk size mismatch index={marker['index']}: "
                f"{identity_input_size} != {expected_identity_size}"
            )
        if corpus_h.hexdigest() != marker["corpus_sha256"]:
            raise SemanticDedupeMergeError(
                f"corpus chunk SHA-256 mismatch index={marker['index']}"
            )
        if identity_h.hexdigest() != marker["identity_sha256"]:
            raise SemanticDedupeMergeError(
                f"identity chunk SHA-256 mismatch index={marker['index']}"
            )
        if input_rows != expected_rows:
            raise SemanticDedupeMergeError(
                f"member row mismatch index={marker['index']}: "
                f"{input_rows} != {expected_rows}"
            )
        if kept_rows + duplicate_rows != input_rows:
            raise SemanticDedupeMergeError(
                f"dedupe accounting mismatch index={marker['index']}"
            )

        conn.commit()
        return {
            "input_rows": input_rows,
            "kept_rows": kept_rows,
            "duplicate_rows": duplicate_rows,
            "next_record": next_record,
            "corpus_output_size": corpus_temp.stat().st_size,
            "identity_output_size": identity_temp.stat().st_size,
        }
    except Exception:
        conn.rollback()
        corpus_temp.unlink(missing_ok=True)
        identity_temp.unlink(missing_ok=True)
        raise


def advance(
    *,
    work_dir: Path,
    adapter_path: Path,
    authority_path: Path,
    state_dir: Path,
    out_corpus: Path,
    out_identity: Path,
    start: str,
    end: str,
    expected_members: int,
    max_seconds: float,
    max_members: int,
    json_backend: str,
    orjson_root: Path,
    batch_size: int,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    adapter_path = adapter_path.resolve()
    authority_path = authority_path.resolve()
    state_dir = state_dir.resolve()
    out_corpus = out_corpus.resolve()
    out_identity = out_identity.resolve()

    if _git_blob_sha1(adapter_path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise SemanticDedupeMergeError(
            "amended adapter Git blob SHA-1 mismatch"
        )
    if _git_blob_sha1(authority_path) != EXPECTED_AUTHORITY_GIT_BLOB_SHA1:
        raise SemanticDedupeMergeError(
            "final-merge authority Git blob SHA-1 mismatch"
        )
    adapter = _load_module(
        adapter_path,
        "p2_37_semantic_dedupe_adapter",
    )
    authority = _load_module(
        authority_path,
        "p2_37_final_merge_authority",
    )

    orjson_module = None
    if json_backend == "orjson":
        root = orjson_root.resolve()
        if not root.is_dir():
            raise SemanticDedupeMergeError(
                f"orjson root not found: {root}"
            )
        import sys

        sys.path.insert(0, str(root))
        try:
            import orjson as imported_orjson
        except Exception as exc:
            raise SemanticDedupeMergeError(
                f"unable to import orjson from {root}: {exc}"
            ) from exc
        orjson_module = imported_orjson
    elif json_backend != "stdlib":
        raise SemanticDedupeMergeError(
            f"unsupported json backend: {json_backend}"
        )

    markers = authority._load_markers(
        work_dir=work_dir,
        expected_members=expected_members,
        start=start,
        end=end,
    )

    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / "state.json"
    db_path = state_dir / "seen.sqlite3"
    corpus_partial = state_dir / "corpus.partial"
    identity_partial = state_dir / "identity.partial"
    current_corpus_temp = state_dir / "current.corpus.tmp"
    current_identity_temp = state_dir / "current.identity.tmp"

    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        _validate_state(
            state,
            work_dir=work_dir,
            adapter_path=adapter_path,
            authority_path=authority_path,
            start=start,
            end=end,
            expected_members=expected_members,
            out_corpus=out_corpus,
            out_identity=out_identity,
        )
    else:
        if out_corpus.exists() or out_identity.exists():
            raise SemanticDedupeMergeError(
                "refusing to initialize over existing final output"
            )
        state = _new_state(
            work_dir=work_dir,
            adapter_path=adapter_path,
            authority_path=authority_path,
            start=start,
            end=end,
            expected_members=expected_members,
            out_corpus=out_corpus,
            out_identity=out_identity,
        )
        authority._atomic_json(state_path, state)

    if state.get("complete"):
        if not out_corpus.is_file() or not out_identity.is_file():
            raise SemanticDedupeMergeError(
                "merge state says complete but final output is missing"
            )
        return {
            "status": "PASS",
            "complete": True,
            "next_index": expected_members,
            "expected_members": expected_members,
            "input_selected_rows": int(state["input_selected_rows"]),
            "selected_rows": int(state["selected_rows"]),
            "duplicate_rows": int(state["duplicate_rows"]),
            "source_rows": int(state["source_rows"]),
            "outside_window_rows": int(state["outside_window_rows"]),
            "selected_source_files": int(state["selected_source_files"]),
            "corpus_size_bytes": out_corpus.stat().st_size,
            "identity_size_bytes": out_identity.stat().st_size,
            "duplicate_policy": DUPLICATE_POLICY,
            "labels_read": False,
            "detection_rules_executed": False,
        }

    conn = _open_db(db_path)
    started = time.monotonic()
    processed = 0
    try:
        _recover(
            state=state,
            corpus_partial=corpus_partial,
            identity_partial=identity_partial,
            conn=conn,
            current_corpus_temp=current_corpus_temp,
            current_identity_temp=current_identity_temp,
        )

        while int(state["next_index"]) < expected_members:
            if processed >= max_members:
                break
            if processed > 0 and time.monotonic() >= started + max_seconds:
                break

            index = int(state["next_index"])
            marker = markers[index]
            corpus_chunk, identity_chunk, _ = authority._paths(
                work_dir,
                index,
            )
            prior_corpus_size = int(state["corpus_committed_size"])
            prior_identity_size = int(state["identity_committed_size"])
            prior_record_index = int(state["record_index"])

            conn.execute(
                "DELETE FROM seen WHERE member_index >= ?",
                (index,),
            )
            conn.commit()
            seen_before = int(
                conn.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
            )
            if seen_before != int(state["seen_count"]):
                raise SemanticDedupeMergeError(
                    f"SQLite seen count mismatch before index {index}: "
                    f"{seen_before} != {state['seen_count']}"
                )

            result = _transform_member_validated(
                corpus_source=corpus_chunk,
                identity_source=identity_chunk,
                marker=marker,
                corpus_temp=current_corpus_temp,
                identity_temp=current_identity_temp,
                adapter=adapter,
                authority=authority,
                conn=conn,
                start_record_index=prior_record_index,
                json_backend=json_backend,
                orjson_module=orjson_module,
                batch_size=batch_size,
            )

            corpus_written = _append_temp(
                temp=current_corpus_temp,
                partial=corpus_partial,
            )
            identity_written = _append_temp(
                temp=current_identity_temp,
                partial=identity_partial,
            )
            if corpus_written != int(result["corpus_output_size"]):
                raise SemanticDedupeMergeError(
                    f"corpus append mismatch index={index}"
                )
            if identity_written != int(result["identity_output_size"]):
                raise SemanticDedupeMergeError(
                    f"identity append mismatch index={index}"
                )

            state["next_index"] = index + 1
            state["corpus_committed_size"] = (
                prior_corpus_size + corpus_written
            )
            state["identity_committed_size"] = (
                prior_identity_size + identity_written
            )
            state["record_index"] = int(result["next_record"])
            state["seen_count"] = seen_before + int(result["kept_rows"])
            state["source_rows"] = (
                int(state["source_rows"])
                + int(marker["source_rows"])
            )
            state["outside_window_rows"] = (
                int(state["outside_window_rows"])
                + int(marker["outside_window_rows"])
            )
            state["input_selected_rows"] = (
                int(state["input_selected_rows"])
                + int(result["input_rows"])
            )
            state["selected_rows"] = (
                int(state["selected_rows"])
                + int(result["kept_rows"])
            )
            state["duplicate_rows"] = (
                int(state["duplicate_rows"])
                + int(result["duplicate_rows"])
            )
            if int(result["kept_rows"]):
                state["selected_source_files"] = (
                    int(state["selected_source_files"]) + 1
                )

            authority._atomic_json(state_path, state)
            current_corpus_temp.unlink(missing_ok=True)
            current_identity_temp.unlink(missing_ok=True)
            processed += 1
            print(
                f"MERGED index={index} "
                f"members={state['next_index']}/{expected_members} "
                f"input_rows={result['input_rows']} "
                f"kept_rows={result['kept_rows']} "
                f"duplicates={result['duplicate_rows']}",
                flush=True,
            )

        if int(state["next_index"]) == expected_members:
            if int(state["seen_count"]) != int(state["selected_rows"]):
                raise SemanticDedupeMergeError(
                    "final seen/selected mismatch"
                )
            if (
                int(state["input_selected_rows"])
                != int(state["selected_rows"])
                + int(state["duplicate_rows"])
            ):
                raise SemanticDedupeMergeError(
                    "final dedupe accounting mismatch"
                )
            for partial, final, committed, label in (
                (
                    corpus_partial,
                    out_corpus,
                    int(state["corpus_committed_size"]),
                    "corpus",
                ),
                (
                    identity_partial,
                    out_identity,
                    int(state["identity_committed_size"]),
                    "identity",
                ),
            ):
                if partial.stat().st_size != committed:
                    raise SemanticDedupeMergeError(
                        f"final {label} partial size mismatch"
                    )
                if final.exists():
                    if final.stat().st_size != committed:
                        raise SemanticDedupeMergeError(
                            f"existing final {label} size mismatch"
                        )
                else:
                    os.replace(partial, final)
            state["complete"] = True
            authority._atomic_json(state_path, state)
    finally:
        conn.close()

    complete = bool(state.get("complete"))
    return {
        "status": "PASS" if complete else "IN_PROGRESS",
        "complete": complete,
        "members_processed_this_invocation": processed,
        "next_index": int(state["next_index"]),
        "expected_members": expected_members,
        "input_selected_rows": int(state["input_selected_rows"]),
        "selected_rows": int(state["selected_rows"]),
        "duplicate_rows": int(state["duplicate_rows"]),
        "source_rows": int(state["source_rows"]),
        "outside_window_rows": int(state["outside_window_rows"]),
        "selected_source_files": int(state["selected_source_files"]),
        "corpus_size_bytes": (
            out_corpus.stat().st_size
            if complete
            else int(state["corpus_committed_size"])
        ),
        "identity_size_bytes": (
            out_identity.stat().st_size
            if complete
            else int(state["identity_committed_size"])
        ),
        "duplicate_policy": DUPLICATE_POLICY,
        "json_backend": json_backend,
        "batch_size": batch_size,
        "labels_read": False,
        "detection_rules_executed": False,
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--merge-authority", required=True)
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--out-corpus", required=True)
    ap.add_argument("--out-identity-map", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--expected-members", type=int, default=672)
    ap.add_argument("--max-seconds", type=float, default=55.0)
    ap.add_argument("--max-members", type=int, default=8)
    ap.add_argument(
        "--json-backend",
        choices=("stdlib", "orjson"),
        default="stdlib",
    )
    ap.add_argument("--orjson-root", default=".")
    ap.add_argument("--batch-size", type=int, default=10000)
    return ap


def main() -> int:
    args = parser().parse_args()
    result = advance(
        work_dir=Path(args.work_dir),
        adapter_path=Path(args.adapter),
        authority_path=Path(args.merge_authority),
        state_dir=Path(args.state_dir),
        out_corpus=Path(args.out_corpus),
        out_identity=Path(args.out_identity_map),
        start=args.start,
        end=args.end,
        expected_members=args.expected_members,
        max_seconds=args.max_seconds,
        max_members=args.max_members,
        json_backend=args.json_backend,
        orjson_root=Path(args.orjson_root),
        batch_size=args.batch_size,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
