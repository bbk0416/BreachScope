#!/usr/bin/env python3
"""Parallel label-blind P2-37 normalization with byte-identical final outputs.

This tool imports the frozen P2-37 adapter and uses its exact row decoder,
Winlogbeat validation, window predicate, provider identity, normalization,
canonical JSON writer, and row digest. Workers only parallelize per-member
preparation. Final corpus/identity outputs are merged in the same sorted
source-member and source-line order as the frozen serial normalize_corpus().
"""
from __future__ import annotations

import argparse
import bz2
import importlib.util
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "31bf09ada2f5f511f0eea8ff492732178d848233"

_G: dict[str, Any] = {}


class ParallelNormalizationError(RuntimeError):
    pass


def _git_blob_sha1(path: Path) -> str:
    import hashlib

    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _load_adapter(path: Path):
    if _git_blob_sha1(path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise ParallelNormalizationError("frozen adapter Git blob SHA-1 mismatch")
    spec = importlib.util.spec_from_file_location("p2_37_frozen_adapter_parallel", path)
    if spec is None or spec.loader is None:
        raise ParallelNormalizationError(f"unable to load frozen adapter: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _worker_init(
    source_text: str,
    adapter_text: str,
    temp_dir_text: str,
    start: str,
    end: str,
) -> None:
    adapter_path = Path(adapter_text)
    adapter = _load_adapter(adapter_path)
    start_dt, end_dt = adapter._window(start, end)
    _G["archive"] = zipfile.ZipFile(source_text)
    _G["adapter"] = adapter
    _G["temp_dir"] = Path(temp_dir_text)
    _G["start"] = start_dt
    _G["end"] = end_dt


def _process_member(task: tuple[int, str]) -> dict[str, Any]:
    index, name = task
    archive: zipfile.ZipFile = _G["archive"]
    adapter = _G["adapter"]
    temp_dir: Path = _G["temp_dir"]
    start_dt = _G["start"]
    end_dt = _G["end"]

    corpus_chunk = temp_dir / f"{index:06d}.corpus.jsonl"
    identity_chunk = temp_dir / f"{index:06d}.identity.jsonl"

    source_rows = 0
    outside_window = 0
    selected_rows = 0

    try:
        with (
            archive.open(name, "r") as binary,
            corpus_chunk.open("wb") as corpus_handle,
            identity_chunk.open("wb") as identity_handle,
        ):
            if name.casefold().endswith(".bz2"):
                text_handle = bz2.open(binary, "rt", encoding="utf-8")
            else:
                import io

                text_handle = io.TextIOWrapper(binary, encoding="utf-8")

            with text_handle as handle:
                for line_number, line in enumerate(handle, 1):
                    text = line.strip()
                    if not text:
                        continue
                    row = adapter._decode_json_line(text, name, line_number)
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
    except Exception:
        corpus_chunk.unlink(missing_ok=True)
        identity_chunk.unlink(missing_ok=True)
        raise

    return {
        "index": index,
        "source_name": name,
        "source_rows": source_rows,
        "outside_window_rows": outside_window,
        "selected_rows": selected_rows,
        "corpus_chunk": str(corpus_chunk),
        "identity_chunk": str(identity_chunk),
    }


def normalize_parallel(
    *,
    winlogbeat_root: Path,
    adapter_path: Path,
    out_corpus: Path,
    out_identity_map: Path,
    start: str,
    end: str,
    workers: int,
) -> dict[str, Any]:
    source = winlogbeat_root.resolve()
    adapter_path = adapter_path.resolve()
    adapter = _load_adapter(adapter_path)
    start_dt, end_dt = adapter._window(start, end)

    if not source.is_file() or source.suffix.casefold() != ".zip":
        raise ParallelNormalizationError(
            "parallel normalizer requires the provider Winlogbeat ZIP source"
        )

    source_names = adapter._winlogbeat_source_names(source)
    if not source_names:
        raise ParallelNormalizationError("no Winlogbeat source members found")

    out_corpus = out_corpus.resolve()
    out_identity_map = out_identity_map.resolve()
    out_corpus.parent.mkdir(parents=True, exist_ok=True)
    out_identity_map.parent.mkdir(parents=True, exist_ok=True)

    worker_count = max(1, min(int(workers), len(source_names)))
    source_rows = 0
    outside_window_rows = 0
    selected_source_files = 0
    selected_rows = 0

    try:
        with tempfile.TemporaryDirectory(
            prefix="p2-37-normalize-parallel-",
            dir=str(out_corpus.parent),
        ) as temp_dir_text:
            temp_dir = Path(temp_dir_text)
            tasks = list(enumerate(source_names))
            with ProcessPoolExecutor(
                max_workers=worker_count,
                initializer=_worker_init,
                initargs=(
                    str(source),
                    str(adapter_path),
                    str(temp_dir),
                    start,
                    end,
                ),
            ) as pool:
                results = list(pool.map(_process_member, tasks))

            results.sort(key=lambda row: int(row["index"]))
            source_rows = sum(int(row["source_rows"]) for row in results)
            outside_window_rows = sum(
                int(row["outside_window_rows"]) for row in results
            )
            selected_source_files = sum(
                1 for row in results if int(row["selected_rows"]) > 0
            )

            db_path = temp_dir / "seen.sqlite3"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("PRAGMA journal_mode=OFF")
                conn.execute("PRAGMA synchronous=OFF")
                conn.execute(
                    "CREATE TABLE seen (provider_identity TEXT PRIMARY KEY)"
                )

                with (
                    out_corpus.open("wb") as corpus_out,
                    out_identity_map.open("wb") as identity_out,
                ):
                    for row in results:
                        source_name = str(row["source_name"])
                        corpus_chunk = Path(str(row["corpus_chunk"]))
                        identity_chunk = Path(str(row["identity_chunk"]))

                        with corpus_chunk.open("rb") as src:
                            shutil.copyfileobj(src, corpus_out, 1024 * 1024)

                        member_identity_rows = 0
                        with identity_chunk.open("r", encoding="utf-8") as src:
                            for line in src:
                                text = line.strip()
                                if not text:
                                    continue
                                temp_row = json.loads(text)
                                provider_id = str(temp_row["provider_identity"])
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
                            raise ParallelNormalizationError(
                                f"identity-row count mismatch for {source_name}: "
                                f"{member_identity_rows} != {row['selected_rows']}"
                            )

                        corpus_chunk.unlink(missing_ok=True)
                        identity_chunk.unlink(missing_ok=True)
            finally:
                conn.close()

        if selected_rows == 0:
            raise adapter.DedalePreparationError(
                "selected DEDALE test window contains zero Winlogbeat events"
            )
    except Exception:
        out_corpus.unlink(missing_ok=True)
        out_identity_map.unlink(missing_ok=True)
        raise

    expected_selected = sum(
        int(row["selected_rows"]) for row in results
    )
    if selected_rows != expected_selected:
        out_corpus.unlink(missing_ok=True)
        out_identity_map.unlink(missing_ok=True)
        raise ParallelNormalizationError(
            f"selected-row count mismatch: {selected_rows} != {expected_selected}"
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
        "normalized_corpus_sha256": adapter._sha256_file(out_corpus),
        "identity_map_sha256": adapter._sha256_file(out_identity_map),
        "workers": worker_count,
        "frozen_adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Parallel byte-identical P2-37 label-blind normalization."
    )
    ap.add_argument("--winlogbeat-root", required=True)
    ap.add_argument(
        "--adapter",
        default=str(Path(__file__).with_name("p2_37_prepare_dedale_holdout.py")),
    )
    ap.add_argument("--out-corpus", required=True)
    ap.add_argument("--out-identity-map", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--workers", type=int, default=8)
    return ap


def main() -> int:
    args = parser().parse_args()
    result = normalize_parallel(
        winlogbeat_root=Path(args.winlogbeat_root),
        adapter_path=Path(args.adapter),
        out_corpus=Path(args.out_corpus),
        out_identity_map=Path(args.out_identity_map),
        start=args.start,
        end=args.end,
        workers=args.workers,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
