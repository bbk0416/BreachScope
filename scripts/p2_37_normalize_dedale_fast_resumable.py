#!/usr/bin/env python3
"""Accelerated front-end for the crash-resumable P2-37 normalizer.

The existing resumable normalizer remains the authority for marker validation
and final merge ordering. This front-end changes only per-member decoding:
- optional 7-Zip file-based BZip2 decompression
- optional orjson JSON decoding

Canonical JSONL bytes are still emitted through the amended frozen adapter.
Provider labels and detection code are never read/run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, BinaryIO

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
_G: dict[str, Any] = {}


class FastNormalizationError(RuntimeError):
    pass


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise FastNormalizationError(f"unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _decode_json_line(raw: bytes, source_name: str, line_number: int) -> dict[str, Any]:
    backend = _G["json_backend"]
    if backend == "orjson":
        try:
            row = _G["orjson"].loads(raw)
        except Exception as exc:
            raise FastNormalizationError(
                f"invalid JSONL row: {source_name}:{line_number}: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise FastNormalizationError(
                f"JSONL row must be an object: {source_name}:{line_number}"
            )
        return row

    adapter = _G["adapter"]
    try:
        return adapter._decode_json_line(
            raw.decode("utf-8"),
            source_name,
            line_number,
        )
    except UnicodeDecodeError as exc:
        raise FastNormalizationError(
            f"invalid UTF-8: {source_name}:{line_number}: {exc}"
        ) from exc


def _worker_init(
    source_text: str,
    adapter_text: str,
    resumable_text: str,
    work_dir_text: str,
    temp_root_text: str,
    start: str,
    end: str,
    json_backend: str,
    orjson_root_text: str,
    seven_zip_text: str,
) -> None:
    adapter_path = Path(adapter_text)
    if _git_blob_sha1(adapter_path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise FastNormalizationError("frozen adapter Git blob SHA-1 mismatch")

    adapter = _load_module(adapter_path, "p2_37_fast_adapter")
    resumable = _load_module(
        Path(resumable_text),
        "p2_37_resumable_authority",
    )
    if resumable.EXPECTED_ADAPTER_GIT_BLOB_SHA1 != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise FastNormalizationError(
            "resumable normalizer adapter pin mismatch"
        )

    if json_backend == "orjson":
        root = Path(orjson_root_text)
        if not root.is_dir():
            raise FastNormalizationError(
                f"orjson root not found: {root}"
            )
        sys.path.insert(0, str(root))
        try:
            import orjson
        except Exception as exc:
            raise FastNormalizationError(
                f"unable to import orjson from {root}: {exc}"
            ) from exc
        _G["orjson"] = orjson

    if seven_zip_text:
        seven_zip = Path(seven_zip_text)
        if not seven_zip.is_file():
            raise FastNormalizationError(
                f"7-Zip executable not found: {seven_zip}"
            )
        _G["seven_zip"] = str(seven_zip)
    else:
        _G["seven_zip"] = ""

    start_dt, end_dt = adapter._window(start, end)
    _G["archive"] = zipfile.ZipFile(source_text)
    _G["adapter"] = adapter
    _G["resumable"] = resumable
    _G["work_dir"] = Path(work_dir_text)
    _G["temp_root"] = Path(temp_root_text)
    _G["start"] = start_dt
    _G["end"] = end_dt
    _G["start_text"] = start
    _G["end_text"] = end
    _G["json_backend"] = json_backend


def _iter_plain_lines(binary: BinaryIO):
    for line in binary:
        yield line


def _process_member(task: tuple[int, str, int]) -> dict[str, Any]:
    index, name, source_file_size = task
    archive: zipfile.ZipFile = _G["archive"]
    adapter = _G["adapter"]
    resumable = _G["resumable"]
    work_dir: Path = _G["work_dir"]
    temp_root: Path = _G["temp_root"]
    start_dt = _G["start"]
    end_dt = _G["end"]
    start_text = str(_G["start_text"])
    end_text = str(_G["end_text"])

    corpus_chunk, identity_chunk, marker_path = resumable._paths(
        work_dir,
        index,
    )
    pid = os.getpid()
    corpus_tmp = work_dir / f"{index:06d}.corpus.tmp.{pid}"
    identity_tmp = work_dir / f"{index:06d}.identity.tmp.{pid}"
    marker_tmp = work_dir / f"{index:06d}.done.tmp.{pid}"
    inner_tmp: Path | None = None
    proc: subprocess.Popen[bytes] | None = None

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
            if name.casefold().endswith(".bz2") and _G["seven_zip"]:
                temp_root.mkdir(parents=True, exist_ok=True)
                fd, temp_name = tempfile.mkstemp(
                    prefix=f"p2-37-{index:06d}-",
                    suffix=".jsonl.bz2",
                    dir=temp_root,
                )
                os.close(fd)
                inner_tmp = Path(temp_name)
                with inner_tmp.open("wb") as dst:
                    shutil.copyfileobj(binary, dst, 1024 * 1024)

                proc = subprocess.Popen(
                    [_G["seven_zip"], "x", "-so", str(inner_tmp)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if proc.stdout is None:
                    raise FastNormalizationError(
                        f"7-Zip stdout unavailable for {name}"
                    )
                line_iter = _iter_plain_lines(proc.stdout)
            elif name.casefold().endswith(".bz2"):
                import bz2

                line_iter = _iter_plain_lines(bz2.BZ2File(binary, "rb"))
            else:
                line_iter = _iter_plain_lines(binary)

            for line_number, line in enumerate(line_iter, 1):
                raw = line.strip()
                if not raw:
                    continue
                row = _decode_json_line(raw, name, line_number)
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

            if proc is not None:
                assert proc.stdout is not None
                proc.stdout.close()
                stderr = b""
                if proc.stderr is not None:
                    stderr = proc.stderr.read()
                    proc.stderr.close()
                rc = proc.wait()
                if rc != 0:
                    raise FastNormalizationError(
                        f"7-Zip BZip2 decode failed for {name}: rc={rc}: "
                        + stderr.decode("utf-8", errors="replace")[:1000]
                    )

            corpus_handle.flush()
            identity_handle.flush()
            os.fsync(corpus_handle.fileno())
            os.fsync(identity_handle.fileno())

        corpus_sha = resumable._sha256(corpus_tmp)
        identity_sha = resumable._sha256(identity_tmp)
        corpus_size = corpus_tmp.stat().st_size
        identity_size = identity_tmp.stat().st_size

        os.replace(corpus_tmp, corpus_chunk)
        os.replace(identity_tmp, identity_chunk)

        marker = {
            **resumable._marker_contract(
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
        with marker_tmp.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(json.dumps(marker, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(marker_tmp, marker_path)
        return marker
    except Exception:
        if proc is not None and proc.poll() is None:
            proc.kill()
        corpus_tmp.unlink(missing_ok=True)
        identity_tmp.unlink(missing_ok=True)
        marker_tmp.unlink(missing_ok=True)
        raise
    finally:
        if inner_tmp is not None:
            inner_tmp.unlink(missing_ok=True)


def normalize_fast_resumable(
    *,
    winlogbeat_root: Path,
    adapter_path: Path,
    resumable_path: Path,
    work_dir: Path,
    temp_root: Path,
    out_corpus: Path,
    out_identity_map: Path,
    start: str,
    end: str,
    workers: int,
    json_backend: str,
    orjson_root: Path,
    seven_zip: Path | None,
    prepare_only: bool = False,
) -> dict[str, Any]:
    source = winlogbeat_root.resolve()
    adapter_path = adapter_path.resolve()
    resumable_path = resumable_path.resolve()
    work_dir = work_dir.resolve()
    temp_root = temp_root.resolve()

    adapter = _load_module(adapter_path, "p2_37_fast_main_adapter")
    resumable = _load_module(
        resumable_path,
        "p2_37_resumable_main_authority",
    )
    if _git_blob_sha1(adapter_path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise FastNormalizationError("frozen adapter Git blob SHA-1 mismatch")
    if resumable.EXPECTED_ADAPTER_GIT_BLOB_SHA1 != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise FastNormalizationError("resumable normalizer adapter pin mismatch")
    start_dt, end_dt = adapter._window(start, end)

    if not source.is_file() or source.suffix.casefold() != ".zip":
        raise FastNormalizationError(
            "fast resumable normalizer requires the provider ZIP source"
        )

    source_names = adapter._winlogbeat_source_names(source)
    if not source_names:
        raise FastNormalizationError("no Winlogbeat source members found")
    with zipfile.ZipFile(source) as archive:
        by_name = {info.filename: info for info in archive.infolist()}
        source_sizes = {
            name: int(by_name[name].file_size)
            for name in source_names
        }

    work_dir.mkdir(parents=True, exist_ok=True)
    results: dict[int, dict[str, Any]] = {}
    pending: list[tuple[int, str, int]] = []
    for index, name in enumerate(source_names):
        marker = resumable._read_valid_marker(
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
                str(resumable_path),
                str(work_dir),
                str(temp_root),
                start,
                end,
                json_backend,
                str(orjson_root),
                str(seven_zip) if seven_zip else "",
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
        raise FastNormalizationError(
            f"missing committed normalization members: {missing[:20]}"
        )
    ordered = [results[i] for i in range(len(source_names))]

    source_rows = sum(int(row["source_rows"]) for row in ordered)
    outside_window_rows = sum(
        int(row["outside_window_rows"]) for row in ordered
    )
    selected_rows_expected = sum(
        int(row["selected_rows"]) for row in ordered
    )

    common = {
        "status": "PASS",
        "detection_rules_executed": False,
        "labels_read": False,
        "window_start": start_dt.isoformat(),
        "window_end": end_dt.isoformat(),
        "source_data_files": len(source_names),
        "source_rows": source_rows,
        "outside_window_rows": outside_window_rows,
        "selected_rows": selected_rows_expected,
        "committed_members": len(ordered),
        "resumed_members": resumed,
        "workers": max(1, min(int(workers), len(source_names))),
        "frozen_adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
        "json_backend": json_backend,
        "seven_zip_enabled": bool(seven_zip),
    }
    if prepare_only:
        return {
            **common,
            "prepare_only": True,
        }

    selected_rows, selected_source_files = resumable._merge(
        adapter=adapter,
        results=ordered,
        work_dir=work_dir,
        out_corpus=out_corpus,
        out_identity_map=out_identity_map,
    )
    if selected_rows != selected_rows_expected:
        raise FastNormalizationError(
            f"selected-row count mismatch: "
            f"{selected_rows} != {selected_rows_expected}"
        )
    return {
        **common,
        "selected_source_files": selected_source_files,
        "selected_rows": selected_rows,
        "normalized_corpus_sha256": adapter._sha256_file(
            out_corpus.resolve()
        ),
        "identity_map_sha256": adapter._sha256_file(
            out_identity_map.resolve()
        ),
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--winlogbeat-root", required=True)
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--resumable-normalizer", required=True)
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--temp-root", required=True)
    ap.add_argument("--out-corpus", required=True)
    ap.add_argument("--out-identity-map", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument(
        "--json-backend",
        choices=("stdlib", "orjson"),
        default="stdlib",
    )
    ap.add_argument("--orjson-root", default=".")
    ap.add_argument("--seven-zip", default="")
    ap.add_argument("--prepare-only", action="store_true")
    return ap


def main() -> int:
    args = parser().parse_args()
    result = normalize_fast_resumable(
        winlogbeat_root=Path(args.winlogbeat_root),
        adapter_path=Path(args.adapter),
        resumable_path=Path(args.resumable_normalizer),
        work_dir=Path(args.work_dir),
        temp_root=Path(args.temp_root),
        out_corpus=Path(args.out_corpus),
        out_identity_map=Path(args.out_identity_map),
        start=args.start,
        end=args.end,
        workers=args.workers,
        json_backend=args.json_backend,
        orjson_root=Path(args.orjson_root),
        seven_zip=Path(args.seven_zip) if args.seven_zip else None,
        prepare_only=args.prepare_only,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
