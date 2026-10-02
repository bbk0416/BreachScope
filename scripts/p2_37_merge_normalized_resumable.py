#!/usr/bin/env python3
"""Crash-resumable final merge for committed P2-37 normalization members.

This tool consumes only authoritative breachscope.p2_37_normalization_member.v1
markers/chunks. It validates each member's corpus and identity bytes while
merging, persists duplicate-provider-identity state in SQLite, and commits one
member at a time. It never reads provider labels and never executes detection.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
EXPECTED_MARKER_SCHEMA = "breachscope.p2_37_normalization_member.v1"
STATE_SCHEMA = "breachscope.p2_37_final_merge_state.v1"


class FinalMergeError(RuntimeError):
    pass


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _sha256_stream(path: Path, *, block: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(block), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise FinalMergeError(f"unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _atomic_json(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _paths(work_dir: Path, index: int) -> tuple[Path, Path, Path]:
    stem = f"{index:06d}"
    return (
        work_dir / f"{stem}.corpus.jsonl",
        work_dir / f"{stem}.identity.jsonl",
        work_dir / f"{stem}.done.json",
    )


def _load_markers(
    *,
    work_dir: Path,
    expected_members: int,
    start: str,
    end: str,
) -> list[dict[str, Any]]:
    markers: list[dict[str, Any]] = []
    for index in range(expected_members):
        corpus, identity, marker_path = _paths(work_dir, index)
        if not marker_path.is_file():
            raise FinalMergeError(f"missing marker: {marker_path.name}")
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise FinalMergeError(
                f"invalid marker JSON: {marker_path.name}: {exc}"
            ) from exc
        expected = {
            "schema": EXPECTED_MARKER_SCHEMA,
            "index": index,
            "start": start,
            "end": end,
            "adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
        }
        for key, value in expected.items():
            if marker.get(key) != value:
                raise FinalMergeError(
                    f"marker contract mismatch: {marker_path.name}: "
                    f"{key}={marker.get(key)!r} expected={value!r}"
                )
        if not corpus.is_file() or not identity.is_file():
            raise FinalMergeError(
                f"marker chunk missing: index={index}"
            )
        for key in (
            "source_name",
            "source_file_size",
            "source_rows",
            "outside_window_rows",
            "selected_rows",
            "corpus_size_bytes",
            "identity_size_bytes",
            "corpus_sha256",
            "identity_sha256",
        ):
            if key not in marker:
                raise FinalMergeError(
                    f"marker field missing: {marker_path.name}: {key}"
                )
        markers.append(marker)
    extra = [
        p.name
        for p in work_dir.glob("*.done.json")
        if int(p.name.split(".", 1)[0]) >= expected_members
    ]
    if extra:
        raise FinalMergeError(
            f"unexpected marker indices beyond expected range: {extra[:10]}"
        )
    return markers


def _new_state(
    *,
    work_dir: Path,
    adapter_path: Path,
    start: str,
    end: str,
    expected_members: int,
    out_corpus: Path,
    out_identity: Path,
) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "work_dir": str(work_dir.resolve()),
        "adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
        "adapter_path": str(adapter_path.resolve()),
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
        "selected_rows": 0,
        "selected_source_files": 0,
        "complete": False,
    }


def _validate_state(
    state: dict[str, Any],
    *,
    work_dir: Path,
    adapter_path: Path,
    start: str,
    end: str,
    expected_members: int,
    out_corpus: Path,
    out_identity: Path,
) -> None:
    expected = _new_state(
        work_dir=work_dir,
        adapter_path=adapter_path,
        start=start,
        end=end,
        expected_members=expected_members,
        out_corpus=out_corpus,
        out_identity=out_identity,
    )
    for key in (
        "schema",
        "work_dir",
        "adapter_git_blob_sha1",
        "adapter_path",
        "start",
        "end",
        "expected_members",
        "out_corpus",
        "out_identity",
    ):
        if state.get(key) != expected[key]:
            raise FinalMergeError(
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
            member_index INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _recover(
    *,
    state: dict[str, Any],
    corpus_partial: Path,
    identity_partial: Path,
    conn: sqlite3.Connection,
    current_identity_temp: Path,
) -> None:
    next_index = int(state["next_index"])
    corpus_size = int(state["corpus_committed_size"])
    identity_size = int(state["identity_committed_size"])

    for path, committed in (
        (corpus_partial, corpus_size),
        (identity_partial, identity_size),
    ):
        if not path.exists():
            if committed != 0:
                raise FinalMergeError(
                    f"partial output missing below committed size: {path}"
                )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        actual = path.stat().st_size
        if actual < committed:
            raise FinalMergeError(
                f"partial output shorter than committed size: "
                f"{path.name}: {actual} < {committed}"
            )
        if actual > committed:
            with path.open("r+b") as handle:
                handle.truncate(committed)
                handle.flush()
                os.fsync(handle.fileno())

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
        raise FinalMergeError(
            f"SQLite seen count mismatch after recovery: "
            f"{seen_count} != {state['seen_count']}"
        )


def _append_corpus_validated(
    *,
    source: Path,
    marker: dict[str, Any],
    corpus_partial: Path,
    committed_size: int,
) -> int:
    expected_size = int(marker["corpus_size_bytes"])
    h = hashlib.sha256()
    written = 0
    try:
        with source.open("rb") as src, corpus_partial.open("ab") as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                h.update(chunk)
                dst.write(chunk)
                written += len(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        if written != expected_size:
            raise FinalMergeError(
                f"corpus chunk size mismatch index={marker['index']}: "
                f"{written} != {expected_size}"
            )
        digest = h.hexdigest()
        if digest != marker["corpus_sha256"]:
            raise FinalMergeError(
                f"corpus chunk SHA-256 mismatch index={marker['index']}: "
                f"{digest} != {marker['corpus_sha256']}"
            )
        return written
    except Exception:
        with corpus_partial.open("r+b") as handle:
            handle.truncate(committed_size)
            handle.flush()
            os.fsync(handle.fileno())
        raise


def _transform_identity_validated(
    *,
    source: Path,
    marker: dict[str, Any],
    temp_out: Path,
    adapter,
    conn: sqlite3.Connection,
    start_record_index: int,
) -> tuple[int, int, int]:
    expected_size = int(marker["identity_size_bytes"])
    expected_rows = int(marker["selected_rows"])
    h = hashlib.sha256()
    input_size = 0
    rows = 0
    next_record = start_record_index

    conn.execute("BEGIN IMMEDIATE")
    try:
        with source.open("rb") as src, temp_out.open("wb") as dst:
            for raw in src:
                h.update(raw)
                input_size += len(raw)
                text = raw.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except Exception as exc:
                    raise FinalMergeError(
                        f"invalid identity JSON index={marker['index']}: "
                        f"row={rows + 1}: {exc}"
                    ) from exc

                provider_id = str(row["provider_identity"])
                try:
                    conn.execute(
                        """
                        INSERT INTO seen(provider_identity, member_index)
                        VALUES (?, ?)
                        """,
                        (provider_id, int(marker["index"])),
                    )
                except sqlite3.IntegrityError as exc:
                    raise FinalMergeError(
                        "duplicate provider identity in selected DEDALE "
                        f"corpus: {provider_id}"
                    ) from exc

                next_record += 1
                dst.write(
                    adapter._json_bytes(
                        {
                            "record_index": next_record,
                            "provider_identity": provider_id,
                            "source_file": str(marker["source_name"]),
                            "source_line": int(row["source_line"]),
                            "source_row_sha256": str(
                                row["source_row_sha256"]
                            ),
                        }
                    )
                )
                rows += 1

            dst.flush()
            os.fsync(dst.fileno())

        if input_size != expected_size:
            raise FinalMergeError(
                f"identity chunk size mismatch index={marker['index']}: "
                f"{input_size} != {expected_size}"
            )
        digest = h.hexdigest()
        if digest != marker["identity_sha256"]:
            raise FinalMergeError(
                f"identity chunk SHA-256 mismatch index={marker['index']}: "
                f"{digest} != {marker['identity_sha256']}"
            )
        if rows != expected_rows:
            raise FinalMergeError(
                f"identity row mismatch index={marker['index']}: "
                f"{rows} != {expected_rows}"
            )
        conn.commit()
        return rows, next_record, temp_out.stat().st_size
    except Exception:
        conn.rollback()
        temp_out.unlink(missing_ok=True)
        raise


def _append_identity_temp(
    *,
    temp_out: Path,
    identity_partial: Path,
) -> int:
    written = 0
    with temp_out.open("rb") as src, identity_partial.open("ab") as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            dst.write(chunk)
            written += len(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    return written


def advance(
    *,
    work_dir: Path,
    adapter_path: Path,
    state_dir: Path,
    out_corpus: Path,
    out_identity: Path,
    start: str,
    end: str,
    expected_members: int,
    max_seconds: float,
    max_members: int,
) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    adapter_path = adapter_path.resolve()
    state_dir = state_dir.resolve()
    out_corpus = out_corpus.resolve()
    out_identity = out_identity.resolve()

    if _git_blob_sha1(adapter_path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise FinalMergeError("amended adapter Git blob SHA-1 mismatch")
    adapter = _load_module(adapter_path, "p2_37_final_merge_adapter")

    markers = _load_markers(
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
    current_identity_temp = state_dir / "current.identity.tmp"

    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        _validate_state(
            state,
            work_dir=work_dir,
            adapter_path=adapter_path,
            start=start,
            end=end,
            expected_members=expected_members,
            out_corpus=out_corpus,
            out_identity=out_identity,
        )
    else:
        if out_corpus.exists() or out_identity.exists():
            raise FinalMergeError(
                "refusing to initialize merge state over existing final output"
            )
        state = _new_state(
            work_dir=work_dir,
            adapter_path=adapter_path,
            start=start,
            end=end,
            expected_members=expected_members,
            out_corpus=out_corpus,
            out_identity=out_identity,
        )
        _atomic_json(state_path, state)

    if state.get("complete"):
        if not out_corpus.is_file() or not out_identity.is_file():
            raise FinalMergeError(
                "merge state says complete but final output is missing"
            )
        return {
            "status": "PASS",
            "complete": True,
            "next_index": expected_members,
            "expected_members": expected_members,
            "selected_rows": int(state["selected_rows"]),
            "source_rows": int(state["source_rows"]),
            "outside_window_rows": int(state["outside_window_rows"]),
            "selected_source_files": int(
                state["selected_source_files"]
            ),
            "corpus_size_bytes": out_corpus.stat().st_size,
            "identity_size_bytes": out_identity.stat().st_size,
            "labels_read": False,
            "detection_rules_executed": False,
        }

    conn = _open_db(db_path)
    started = time.monotonic()
    processed = 0
    try:
        if int(state["next_index"]) == expected_members:
            current_identity_temp.unlink(missing_ok=True)
            conn.execute(
                "DELETE FROM seen WHERE member_index >= ?",
                (expected_members,),
            )
            conn.commit()
            seen_count = int(
                conn.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
            )
            if seen_count != int(state["seen_count"]):
                raise FinalMergeError(
                    "SQLite seen count mismatch during finalization recovery: "
                    f"{seen_count} != {state['seen_count']}"
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
                if final.exists():
                    if final.stat().st_size != committed:
                        raise FinalMergeError(
                            f"existing final {label} size mismatch"
                        )
                    if partial.exists():
                        raise FinalMergeError(
                            f"both partial and final {label} outputs exist"
                        )
                else:
                    if not partial.exists():
                        raise FinalMergeError(
                            f"missing partial {label} during finalization"
                        )
                    if partial.stat().st_size != committed:
                        raise FinalMergeError(
                            f"partial {label} size mismatch during finalization"
                        )
                    os.replace(partial, final)

            state["complete"] = True
            _atomic_json(state_path, state)
        else:
            _recover(
                state=state,
                corpus_partial=corpus_partial,
                identity_partial=identity_partial,
                conn=conn,
                current_identity_temp=current_identity_temp,
            )

        while int(state["next_index"]) < expected_members:
            if processed >= max_members:
                break
            if processed > 0 and time.monotonic() >= started + max_seconds:
                break

            index = int(state["next_index"])
            marker = markers[index]
            corpus_chunk, identity_chunk, _ = _paths(work_dir, index)

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
                raise FinalMergeError(
                    f"SQLite seen count mismatch before index {index}: "
                    f"{seen_before} != {state['seen_count']}"
                )

            rows, next_record, identity_output_size = (
                _transform_identity_validated(
                    source=identity_chunk,
                    marker=marker,
                    temp_out=current_identity_temp,
                    adapter=adapter,
                    conn=conn,
                    start_record_index=prior_record_index,
                )
            )

            corpus_written = _append_corpus_validated(
                source=corpus_chunk,
                marker=marker,
                corpus_partial=corpus_partial,
                committed_size=prior_corpus_size,
            )
            identity_written = _append_identity_temp(
                temp_out=current_identity_temp,
                identity_partial=identity_partial,
            )

            if identity_written != identity_output_size:
                with identity_partial.open("r+b") as handle:
                    handle.truncate(prior_identity_size)
                    handle.flush()
                    os.fsync(handle.fileno())
                with corpus_partial.open("r+b") as handle:
                    handle.truncate(prior_corpus_size)
                    handle.flush()
                    os.fsync(handle.fileno())
                conn.execute(
                    "DELETE FROM seen WHERE member_index = ?",
                    (index,),
                )
                conn.commit()
                raise FinalMergeError(
                    f"identity append mismatch index={index}: "
                    f"{identity_written} != {identity_output_size}"
                )

            state["next_index"] = index + 1
            state["corpus_committed_size"] = (
                prior_corpus_size + corpus_written
            )
            state["identity_committed_size"] = (
                prior_identity_size + identity_written
            )
            state["record_index"] = next_record
            state["seen_count"] = seen_before + rows
            state["source_rows"] = (
                int(state["source_rows"])
                + int(marker["source_rows"])
            )
            state["outside_window_rows"] = (
                int(state["outside_window_rows"])
                + int(marker["outside_window_rows"])
            )
            state["selected_rows"] = (
                int(state["selected_rows"])
                + int(marker["selected_rows"])
            )
            if int(marker["selected_rows"]):
                state["selected_source_files"] = (
                    int(state["selected_source_files"]) + 1
                )
            _atomic_json(state_path, state)
            current_identity_temp.unlink(missing_ok=True)
            processed += 1
            print(
                f"MERGED index={index} "
                f"members={state['next_index']}/{expected_members} "
                f"selected_rows={marker['selected_rows']}",
                flush=True,
            )

        if int(state["next_index"]) == expected_members:
            if int(state["seen_count"]) != int(state["selected_rows"]):
                raise FinalMergeError(
                    f"final seen/selected mismatch: "
                    f"{state['seen_count']} != {state['selected_rows']}"
                )
            if corpus_partial.stat().st_size != int(
                state["corpus_committed_size"]
            ):
                raise FinalMergeError("final corpus partial size mismatch")
            if identity_partial.stat().st_size != int(
                state["identity_committed_size"]
            ):
                raise FinalMergeError("final identity partial size mismatch")

            if out_corpus.exists():
                if out_corpus.stat().st_size != int(
                    state["corpus_committed_size"]
                ):
                    raise FinalMergeError(
                        "existing final corpus size mismatch"
                    )
            else:
                os.replace(corpus_partial, out_corpus)

            if out_identity.exists():
                if out_identity.stat().st_size != int(
                    state["identity_committed_size"]
                ):
                    raise FinalMergeError(
                        "existing final identity size mismatch"
                    )
            else:
                os.replace(identity_partial, out_identity)

            state["complete"] = True
            _atomic_json(state_path, state)
    finally:
        conn.close()

    complete = bool(state.get("complete"))
    return {
        "status": "PASS" if complete else "IN_PROGRESS",
        "complete": complete,
        "members_processed_this_invocation": processed,
        "next_index": int(state["next_index"]),
        "expected_members": expected_members,
        "selected_rows": int(state["selected_rows"]),
        "source_rows": int(state["source_rows"]),
        "outside_window_rows": int(state["outside_window_rows"]),
        "selected_source_files": int(state["selected_source_files"]),
        "corpus_size_bytes": (
            out_corpus.stat().st_size
            if complete else int(state["corpus_committed_size"])
        ),
        "identity_size_bytes": (
            out_identity.stat().st_size
            if complete else int(state["identity_committed_size"])
        ),
        "elapsed_seconds": time.monotonic() - started,
        "labels_read": False,
        "detection_rules_executed": False,
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--out-corpus", required=True)
    ap.add_argument("--out-identity-map", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--expected-members", type=int, default=672)
    ap.add_argument("--max-seconds", type=float, default=55.0)
    ap.add_argument("--max-members", type=int, default=8)
    return ap


def main() -> int:
    args = parser().parse_args()
    result = advance(
        work_dir=Path(args.work_dir),
        adapter_path=Path(args.adapter),
        state_dir=Path(args.state_dir),
        out_corpus=Path(args.out_corpus),
        out_identity=Path(args.out_identity_map),
        start=args.start,
        end=args.end,
        expected_members=args.expected_members,
        max_seconds=args.max_seconds,
        max_members=args.max_members,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
