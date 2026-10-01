#!/usr/bin/env python3
"""Crash-resumable, byte-identical P2-37 DEDALE normalizer.

Each source member is committed through an atomic done marker only after both
temporary chunk files have been fsynced, renamed, and hashed. A later run
rehashes committed chunks before reuse. Final corpus and identity outputs are
merged in the same sorted source-member/source-line order as the frozen
parallel normalizer. Provider labels and detection code are never read/run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "31bf09ada2f5f511f0eea8ff492732178d848233"
MARKER_SCHEMA = "breachscope.p2_37_normalization_member.v1"
_G: dict[str, Any] = {}


class ResumableNormalizationError(RuntimeError):
    pass


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_adapter(path: Path):
    if _git_blob_sha1(path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise ResumableNormalizationError(
            "frozen adapter Git blob SHA-1 mismatch"
        )
    spec = importlib.util.spec_from_file_location(
        "p2_37_frozen_adapter_resumable",
        path,
    )
    if spec is None or spec.loader is None:
        raise ResumableNormalizationError(
            f"unable to load frozen adapter: {path}"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _paths(work_dir: Path, index: int) -> tuple[Path, Path, Path]:
    stem = f"{index:06d}"
    return (
        work_dir / f"{stem}.corpus.jsonl",
        work_dir / f"{stem}.identity.jsonl",
        work_dir / f"{stem}.done.json",
    )


def _marker_contract(
    *,
    index: int,
    source_name: str,
    source_file_size: int,
    start: str,
    end: str,
) -> dict[str, Any]:
    return {
        "schema": MARKER_SCHEMA,
        "index": index,
        "source_name": source_name,
        "source_file_size": source_file_size,
        "start": start,
        "end": end,
        "adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
    }


def _read_valid_marker(
    *,
    work_dir: Path,
    index: int,
    source_name: str,
    source_file_size: int,
    start: str,
    end: str,
) -> dict[str, Any] | None:
    corpus, identity, marker_path = _paths(work_dir, index)
    if not marker_path.is_file():
        return None
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    contract = _marker_contract(
        index=index,
        source_name=source_name,
        source_file_size=source_file_size,
        start=start,
        end=end,
    )
    for key, expected in contract.items():
        if marker.get(key) != expected:
            return None

    if not corpus.is_file() or not identity.is_file():
        return None
    if corpus.stat().st_size != int(marker.get("corpus_size_bytes", -1)):
        return None
    if identity.stat().st_size != int(marker.get("identity_size_bytes", -1)):
        return None
    if _sha256(corpus) != marker.get("corpus_sha256"):
        return None
    if _sha256(identity) != marker.get("identity_sha256"):
        return None
    return marker


def _worker_init(
    source_text: str,
    adapter_text: str,
    work_dir_text: str,
    start: str,
    end: str,
) -> None:
    adapter_path = Path(adapter_text)
    adapter = _load_adapter(adapter_path)
    start_dt, end_dt = adapter._window(start, end)
    _G["archive"] = zipfile.ZipFile(source_text)
    _G["adapter"] = adapter
    _G["work_dir"] = Path(work_dir_text)
    _G["start"] = start_dt
    _G["end"] = end_dt
    _G["start_text"] = start
    _G["end_text"] = end


def _process_member(
    task: tuple[int, str, int],
) -> dict[str, Any]:
    index, name, source_file_size = task
    archive: zipfile.ZipFile = _G["archive"]
    adapter = _G["adapter"]
    work_dir: Path = _G["work_dir"]
    start_dt = _G["start"]
    end_dt = _G["end"]
    start_text = str(_G["start_text"])
    end_text = str(_G["end_text"])

    corpus_chunk, identity_chunk, marker_path = _paths(work_dir, index)
    pid = os.getpid()
    corpus_tmp = work_dir / f"{index:06d}.corpus.tmp.{pid}"
    identity_tmp = work_dir / f"{index:06d}.identity.tmp.{pid}"
    marker_tmp = work_dir / f"{index:06d}.done.tmp.{pid}"

    for path in (corpus_tmp, identity_tmp, marker_tmp):
        path.unlink(missing_ok=True)

    source_rows = 0
    outside_window = 0
    selected_rows = 0
    try:
        with (
            archive.open(name, "r") as binary,
            corpus_tmp.open("wb") as corpus_handle,
            identity_tmp.open("wb") as identity_handle,
        ):
            if name.casefold().endswith(".bz2"):
                import bz2

                text_handle = bz2.open(binary, "rt", encoding="utf-8")
            else:
                import io

                text_handle = io.TextIOWrapper(binary, encoding="utf-8")

            with text_handle as handle:
                for line_number, line in enumerate(handle, 1):
                    text = line.strip()
                    if not text:
                        continue
                    row = adapter._decode_json_line(
                        text,
                        name,
                        line_number,
                    )
                    source_rows += 1
                    adapter._require_winlogbeat(row)
                    if not adapter._in_window(row, start_dt, end_dt):
                        outside_window += 1
                        continue

                    provider_id = adapter.provider_identity(row)
                    normalized = adapter.normalize_winlogbeat_row(row)
                    corpus_handle.write(adapter._json_bytes(normalized))
                    identity_handle.write(
                        adapter._json_bytes(
                            {
                                "provider_identity": provider_id,
                                "source_line": line_number,
                                "source_row_sha256": adapter._row_digest(row),
                            }
                        )
                    )
                    selected_rows += 1

            corpus_handle.flush()
            identity_handle.flush()
            os.fsync(corpus_handle.fileno())
            os.fsync(identity_handle.fileno())

        corpus_sha = _sha256(corpus_tmp)
        identity_sha = _sha256(identity_tmp)
        corpus_size = corpus_tmp.stat().st_size
        identity_size = identity_tmp.stat().st_size

        os.replace(corpus_tmp, corpus_chunk)
        os.replace(identity_tmp, identity_chunk)

        marker = {
            **_marker_contract(
                index=index,
                source_name=name,
                source_file_size=source_file_size,
                start=start_text,
                end=end_text,
            ),
            "source_rows": source_rows,
            "outside_window_rows": outside_window,
            "selected_rows": selected_rows,
            "corpus_size_bytes": corpus_size,
            "identity_size_bytes": identity_size,
            "corpus_sha256": corpus_sha,
            "identity_sha256": identity_sha,
        }
        with marker_tmp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(marker, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(marker_tmp, marker_path)
        return marker
    except Exception:
        corpus_tmp.unlink(missing_ok=True)
        identity_tmp.unlink(missing_ok=True)
        marker_tmp.unlink(missing_ok=True)
        raise


def _prepare(
    *,
    source: Path,
    source_names: list[str],
    source_sizes: dict[str, int],
    adapter_path: Path,
    work_dir: Path,
    start: str,
    end: str,
    workers: int,
) -> tuple[list[dict[str, Any]], int]:
    work_dir.mkdir(parents=True, exist_ok=True)
    results: dict[int, dict[str, Any]] = {}
    pending: list[tuple[int, str, int]] = []

    for index, name in enumerate(source_names):
        marker = _read_valid_marker(
            work_dir=work_dir,
            index=index,
            source_name=name,
            source_file_size=source_sizes[name],
            start=start,
            end=end,
        )
        if marker is None:
            pending.append((index, name, source_sizes[name]))
        else:
            results[index] = marker

    resumed = len(results)
    if pending:
        worker_count = max(1, min(int(workers), len(pending)))
        with ProcessPoolExecutor(
            max_workers=worker_count,
            initializer=_worker_init,
            initargs=(
                str(source),
                str(adapter_path),
                str(work_dir),
                start,
                end,
            ),
        ) as pool:
            futures = {
                pool.submit(_process_member, task): task[0]
                for task in pending
            }
            try:
                for future in as_completed(futures):
                    result = future.result()
                    results[int(result["index"])] = result
                    print(
                        "PROGRESS "
                        f"members={len(results)}/{len(source_names)} "
                        f"index={result['index']} "
                        f"selected_rows={result['selected_rows']}",
                        flush=True,
                    )
            except Exception:
                for future in futures:
                    future.cancel()
                raise

    missing = [
        index for index in range(len(source_names))
        if index not in results
    ]
    if missing:
        raise ResumableNormalizationError(
            f"missing committed normalization members: {missing[:20]}"
        )
    return [results[i] for i in range(len(source_names))], resumed


def _merge(
    *,
    adapter,
    results: list[dict[str, Any]],
    work_dir: Path,
    out_corpus: Path,
    out_identity_map: Path,
) -> tuple[int, int]:
    out_corpus = out_corpus.resolve()
    out_identity_map = out_identity_map.resolve()
    if out_corpus.exists() or out_identity_map.exists():
        raise ResumableNormalizationError(
            "refusing to overwrite existing canonical normalization output"
        )
    out_corpus.parent.mkdir(parents=True, exist_ok=True)
    out_identity_map.parent.mkdir(parents=True, exist_ok=True)

    corpus_tmp = out_corpus.with_suffix(out_corpus.suffix + ".tmp")
    identity_tmp = out_identity_map.with_suffix(
        out_identity_map.suffix + ".tmp"
    )
    corpus_tmp.unlink(missing_ok=True)
    identity_tmp.unlink(missing_ok=True)

    db_path = work_dir / "merge-seen.sqlite3"
    db_path.unlink(missing_ok=True)
    conn = sqlite3.connect(db_path)
    selected_rows = 0
    selected_source_files = 0
    try:
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute(
            "CREATE TABLE seen (provider_identity TEXT PRIMARY KEY)"
        )

        with (
            corpus_tmp.open("wb") as corpus_out,
            identity_tmp.open("wb") as identity_out,
        ):
            for row in results:
                index = int(row["index"])
                source_name = str(row["source_name"])
                corpus_chunk, identity_chunk, _ = _paths(work_dir, index)

                with corpus_chunk.open("rb") as src:
                    shutil.copyfileobj(src, corpus_out, 1024 * 1024)

                member_identity_rows = 0
                with identity_chunk.open("r", encoding="utf-8") as src:
                    for line in src:
                        text = line.strip()
                        if not text:
                            continue
                        temp_row = json.loads(text)
                        provider_id = str(
                            temp_row["provider_identity"]
                        )
                        try:
                            conn.execute(
                                "INSERT INTO seen(provider_identity) VALUES (?)",
                                (provider_id,),
                            )
                        except sqlite3.IntegrityError as exc:
                            raise adapter.DedalePreparationError(
                                "duplicate provider identity in selected "
                                f"DEDALE corpus: {provider_id}"
                            ) from exc

                        selected_rows += 1
                        member_identity_rows += 1
                        identity_out.write(
                            adapter._json_bytes(
                                {
                                    "record_index": selected_rows,
                                    "provider_identity": provider_id,
                                    "source_file": source_name,
                                    "source_line": int(
                                        temp_row["source_line"]
                                    ),
                                    "source_row_sha256": str(
                                        temp_row["source_row_sha256"]
                                    ),
                                }
                            )
                        )

                if member_identity_rows != int(row["selected_rows"]):
                    raise ResumableNormalizationError(
                        "identity-row count mismatch for "
                        f"{source_name}: {member_identity_rows} "
                        f"!= {row['selected_rows']}"
                    )
                if member_identity_rows:
                    selected_source_files += 1

            corpus_out.flush()
            identity_out.flush()
            os.fsync(corpus_out.fileno())
            os.fsync(identity_out.fileno())
        conn.commit()

        if selected_rows == 0:
            raise adapter.DedalePreparationError(
                "selected DEDALE test window contains zero Winlogbeat events"
            )

        expected_selected = sum(
            int(row["selected_rows"]) for row in results
        )
        if selected_rows != expected_selected:
            raise ResumableNormalizationError(
                f"selected-row count mismatch: "
                f"{selected_rows} != {expected_selected}"
            )

        os.replace(corpus_tmp, out_corpus)
        os.replace(identity_tmp, out_identity_map)
    except Exception:
        corpus_tmp.unlink(missing_ok=True)
        identity_tmp.unlink(missing_ok=True)
        out_corpus.unlink(missing_ok=True)
        out_identity_map.unlink(missing_ok=True)
        raise
    finally:
        conn.close()
        db_path.unlink(missing_ok=True)

    return selected_rows, selected_source_files


def normalize_resumable(
    *,
    winlogbeat_root: Path,
    adapter_path: Path,
    work_dir: Path,
    out_corpus: Path,
    out_identity_map: Path,
    start: str,
    end: str,
    workers: int,
    prepare_only: bool = False,
) -> dict[str, Any]:
    source = winlogbeat_root.resolve()
    adapter_path = adapter_path.resolve()
    work_dir = work_dir.resolve()
    adapter = _load_adapter(adapter_path)
    start_dt, end_dt = adapter._window(start, end)

    if not source.is_file() or source.suffix.casefold() != ".zip":
        raise ResumableNormalizationError(
            "resumable normalizer requires the provider Winlogbeat ZIP source"
        )

    source_names = adapter._winlogbeat_source_names(source)
    if not source_names:
        raise ResumableNormalizationError(
            "no Winlogbeat source members found"
        )
    with zipfile.ZipFile(source) as archive:
        by_name = {info.filename: info for info in archive.infolist()}
        source_sizes = {
            name: int(by_name[name].file_size)
            for name in source_names
        }

    results, resumed = _prepare(
        source=source,
        source_names=source_names,
        source_sizes=source_sizes,
        adapter_path=adapter_path,
        work_dir=work_dir,
        start=start,
        end=end,
        workers=workers,
    )

    source_rows = sum(int(row["source_rows"]) for row in results)
    outside_window_rows = sum(
        int(row["outside_window_rows"]) for row in results
    )
    selected_rows_expected = sum(
        int(row["selected_rows"]) for row in results
    )

    if prepare_only:
        return {
            "status": "PASS",
            "detection_rules_executed": False,
            "labels_read": False,
            "prepare_only": True,
            "window_start": start_dt.isoformat(),
            "window_end": end_dt.isoformat(),
            "source_data_files": len(source_names),
            "source_rows": source_rows,
            "outside_window_rows": outside_window_rows,
            "selected_rows": selected_rows_expected,
            "committed_members": len(results),
            "resumed_members": resumed,
            "workers": max(1, min(int(workers), len(source_names))),
            "frozen_adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
        }

    selected_rows, selected_source_files = _merge(
        adapter=adapter,
        results=results,
        work_dir=work_dir,
        out_corpus=out_corpus,
        out_identity_map=out_identity_map,
    )
    return {
        "status": "PASS",
        "detection_rules_executed": False,
        "labels_read": False,
        "window_start": start_dt.isoformat(),
        "window_end": end_dt.isoformat(),
        "source_data_files": len(source_names),
        "selected_source_files": selected_source_files,
        "source_rows": source_rows,
        "outside_window_rows": outside_window_rows,
        "selected_rows": selected_rows,
        "normalized_corpus_sha256": adapter._sha256_file(
            out_corpus.resolve()
        ),
        "identity_map_sha256": adapter._sha256_file(
            out_identity_map.resolve()
        ),
        "workers": max(1, min(int(workers), len(source_names))),
        "resumed_members": resumed,
        "committed_members": len(results),
        "frozen_adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "Crash-resumable, byte-identical P2-37 label-blind normalization."
        )
    )
    ap.add_argument("--winlogbeat-root", required=True)
    ap.add_argument(
        "--adapter",
        default=str(
            Path(__file__).with_name(
                "p2_37_prepare_dedale_holdout.py"
            )
        ),
    )
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--out-corpus", required=True)
    ap.add_argument("--out-identity-map", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--prepare-only", action="store_true")
    return ap


def main() -> int:
    args = parser().parse_args()
    result = normalize_resumable(
        winlogbeat_root=Path(args.winlogbeat_root),
        adapter_path=Path(args.adapter),
        work_dir=Path(args.work_dir),
        out_corpus=Path(args.out_corpus),
        out_identity_map=Path(args.out_identity_map),
        start=args.start,
        end=args.end,
        workers=args.workers,
        prepare_only=args.prepare_only,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
