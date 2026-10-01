#!/usr/bin/env python3
"""Time-sliced P2-37 normalization compatible with canonical member markers.

This helper exists for execution environments with short command lifetimes.
It checkpoints *inside* a source member using raw-source byte offsets and
hashed output slices. Once a member reaches EOF, it emits the same canonical
member chunk files and the same breachscope.p2_37_normalization_member.v1
done marker consumed by p2_37_normalize_dedale_resumable.py.

Provider labels and detection code are never read or executed.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

EXPECTED_ADAPTER_GIT_BLOB_SHA1 = "8216eea575ce4dcd8dfb75cdc15c0d6f402c1432"
STATE_SCHEMA = "breachscope.p2_37_normalization_slice_state.v1"


class SlicedNormalizationError(RuntimeError):
    pass


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SlicedNormalizationError(f"unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1((f"blob {len(data)}\0").encode() + data).hexdigest()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _decode_json(
    raw: bytes,
    *,
    source_name: str,
    line_number: int,
    backend: str,
    adapter,
    orjson_module,
) -> dict[str, Any]:
    if backend == "orjson":
        try:
            row = orjson_module.loads(raw)
        except Exception as exc:
            raise SlicedNormalizationError(
                f"invalid JSONL row: {source_name}:{line_number}: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise SlicedNormalizationError(
                f"JSONL row must be an object: {source_name}:{line_number}"
            )
        return row
    try:
        return adapter._decode_json_line(
            raw.decode("utf-8"),
            source_name,
            line_number,
        )
    except UnicodeDecodeError as exc:
        raise SlicedNormalizationError(
            f"invalid UTF-8: {source_name}:{line_number}: {exc}"
        ) from exc


def _member_dir(slice_root: Path, index: int) -> Path:
    return slice_root / f"{index:06d}"


def _contract(
    *,
    index: int,
    source_name: str,
    source_file_size: int,
    start: str,
    end: str,
) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "index": index,
        "source_name": source_name,
        "source_file_size": source_file_size,
        "start": start,
        "end": end,
        "adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
    }


def _load_state(
    *,
    member_dir: Path,
    index: int,
    source_name: str,
    source_file_size: int,
    start: str,
    end: str,
) -> dict[str, Any] | None:
    state_path = member_dir / "state.json"
    if not state_path.is_file():
        return None
    state = json.loads(state_path.read_text(encoding="utf-8"))
    for key, expected in _contract(
        index=index,
        source_name=source_name,
        source_file_size=source_file_size,
        start=start,
        end=end,
    ).items():
        if state.get(key) != expected:
            raise SlicedNormalizationError(
                f"slice-state contract mismatch for {source_name}: {key}"
            )

    raw_path = member_dir / "source.jsonl"
    if not raw_path.is_file():
        raise SlicedNormalizationError(
            f"slice raw cache missing for {source_name}"
        )
    if raw_path.stat().st_size != int(state["raw_size_bytes"]):
        raise SlicedNormalizationError(
            f"slice raw size mismatch for {source_name}"
        )

    slices = state.get("slices")
    if not isinstance(slices, list):
        raise SlicedNormalizationError(
            f"slice list missing for {source_name}"
        )
    for row in slices:
        number = int(row["number"])
        corpus = member_dir / f"slice-{number:06d}.corpus"
        identity = member_dir / f"slice-{number:06d}.identity"
        if not corpus.is_file() or not identity.is_file():
            raise SlicedNormalizationError(
                f"committed slice files missing for {source_name}:{number}"
            )
        if corpus.stat().st_size != int(row["corpus_size_bytes"]):
            raise SlicedNormalizationError(
                f"corpus slice size mismatch for {source_name}:{number}"
            )
        if identity.stat().st_size != int(row["identity_size_bytes"]):
            raise SlicedNormalizationError(
                f"identity slice size mismatch for {source_name}:{number}"
            )
        if _sha256(corpus) != row["corpus_sha256"]:
            raise SlicedNormalizationError(
                f"corpus slice hash mismatch for {source_name}:{number}"
            )
        if _sha256(identity) != row["identity_sha256"]:
            raise SlicedNormalizationError(
                f"identity slice hash mismatch for {source_name}:{number}"
            )
    return state


def _extract_raw(
    *,
    source: Path,
    source_name: str,
    member_dir: Path,
    seven_zip: Path | None,
) -> tuple[int, str]:
    member_dir.mkdir(parents=True, exist_ok=True)
    raw = member_dir / "source.jsonl"
    raw_tmp = member_dir / "source.jsonl.tmp"
    inner_tmp = member_dir / "source.jsonl.bz2.tmp"
    raw.unlink(missing_ok=True)
    raw_tmp.unlink(missing_ok=True)
    inner_tmp.unlink(missing_ok=True)

    with zipfile.ZipFile(source) as archive:
        with archive.open(source_name, "r") as binary:
            if source_name.casefold().endswith(".bz2") and seven_zip:
                with inner_tmp.open("wb") as dst:
                    shutil.copyfileobj(binary, dst, 1024 * 1024)
                    dst.flush()
                    os.fsync(dst.fileno())
                with raw_tmp.open("wb") as dst:
                    proc = subprocess.run(
                        [str(seven_zip), "x", "-so", str(inner_tmp)],
                        stdout=dst,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    dst.flush()
                    os.fsync(dst.fileno())
                if proc.returncode != 0:
                    raise SlicedNormalizationError(
                        f"7-Zip BZip2 decode failed for {source_name}: "
                        f"rc={proc.returncode}: "
                        + proc.stderr.decode("utf-8", errors="replace")[:1000]
                    )
            elif source_name.casefold().endswith(".bz2"):
                with (
                    bz2.BZ2File(binary, "rb") as src,
                    raw_tmp.open("wb") as dst,
                ):
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                    dst.flush()
                    os.fsync(dst.fileno())
            else:
                with raw_tmp.open("wb") as dst:
                    shutil.copyfileobj(binary, dst, 1024 * 1024)
                    dst.flush()
                    os.fsync(dst.fileno())

    inner_tmp.unlink(missing_ok=True)
    raw_size = raw_tmp.stat().st_size
    raw_sha = _sha256(raw_tmp)
    os.replace(raw_tmp, raw)
    return raw_size, raw_sha


def _new_state(
    *,
    index: int,
    source_name: str,
    source_file_size: int,
    start: str,
    end: str,
    raw_size: int,
    raw_sha256: str,
) -> dict[str, Any]:
    return {
        **_contract(
            index=index,
            source_name=source_name,
            source_file_size=source_file_size,
            start=start,
            end=end,
        ),
        "raw_size_bytes": raw_size,
        "raw_sha256": raw_sha256,
        "next_offset": 0,
        "next_line_number": 0,
        "source_rows": 0,
        "outside_window_rows": 0,
        "selected_rows": 0,
        "eof": False,
        "slices": [],
    }


def _process_slice(
    *,
    member_dir: Path,
    state: dict[str, Any],
    adapter,
    start_dt,
    end_dt,
    backend: str,
    orjson_module,
    max_rows: int,
    deadline: float,
) -> tuple[dict[str, Any], int]:
    raw_path = member_dir / "source.jsonl"
    slice_number = len(state["slices"])
    corpus_tmp = member_dir / f"slice-{slice_number:06d}.corpus.tmp"
    identity_tmp = member_dir / f"slice-{slice_number:06d}.identity.tmp"
    corpus_final = member_dir / f"slice-{slice_number:06d}.corpus"
    identity_final = member_dir / f"slice-{slice_number:06d}.identity"
    for path in (
        corpus_tmp,
        identity_tmp,
        corpus_final,
        identity_final,
    ):
        if path.exists():
            raise SlicedNormalizationError(
                f"unexpected slice path already exists: {path}"
            )

    source_name = str(state["source_name"])
    physical_line = int(state["next_line_number"])
    source_rows_delta = 0
    outside_delta = 0
    selected_delta = 0
    processed_nonblank = 0
    eof = False

    with (
        raw_path.open("rb") as source_handle,
        corpus_tmp.open("wb") as corpus_handle,
        identity_tmp.open("wb") as identity_handle,
    ):
        source_handle.seek(int(state["next_offset"]))
        start_offset = source_handle.tell()
        start_line = physical_line

        while processed_nonblank < max_rows:
            if time.monotonic() >= deadline:
                break
            line = source_handle.readline()
            if line == b"":
                eof = True
                break
            physical_line += 1
            raw = line.strip()
            if not raw:
                continue
            row = _decode_json(
                raw,
                source_name=source_name,
                line_number=physical_line,
                backend=backend,
                adapter=adapter,
                orjson_module=orjson_module,
            )
            processed_nonblank += 1
            source_rows_delta += 1
            adapter._require_winlogbeat(row)
            if not adapter._in_window(row, start_dt, end_dt):
                outside_delta += 1
                continue

            provider_id = adapter.provider_identity(row)
            normalized = adapter.normalize_winlogbeat_row(row)
            corpus_handle.write(adapter._json_bytes(normalized))
            identity_handle.write(
                adapter._json_bytes(
                    {
                        "provider_identity": provider_id,
                        "source_line": physical_line,
                        "source_row_sha256": adapter._row_digest(row),
                    }
                )
            )
            selected_delta += 1

        end_offset = source_handle.tell()
        corpus_handle.flush()
        identity_handle.flush()
        os.fsync(corpus_handle.fileno())
        os.fsync(identity_handle.fileno())

    if (
        end_offset == int(state["next_offset"])
        and not eof
    ):
        corpus_tmp.unlink(missing_ok=True)
        identity_tmp.unlink(missing_ok=True)
        return state, 0

    corpus_size = corpus_tmp.stat().st_size
    identity_size = identity_tmp.stat().st_size
    corpus_sha = _sha256(corpus_tmp)
    identity_sha = _sha256(identity_tmp)
    os.replace(corpus_tmp, corpus_final)
    os.replace(identity_tmp, identity_final)

    slice_row = {
        "number": slice_number,
        "start_offset": start_offset,
        "end_offset": end_offset,
        "start_line_number": start_line,
        "end_line_number": physical_line,
        "source_rows": source_rows_delta,
        "outside_window_rows": outside_delta,
        "selected_rows": selected_delta,
        "corpus_size_bytes": corpus_size,
        "identity_size_bytes": identity_size,
        "corpus_sha256": corpus_sha,
        "identity_sha256": identity_sha,
    }
    new_state = dict(state)
    new_state["next_offset"] = end_offset
    new_state["next_line_number"] = physical_line
    new_state["source_rows"] = (
        int(state["source_rows"]) + source_rows_delta
    )
    new_state["outside_window_rows"] = (
        int(state["outside_window_rows"]) + outside_delta
    )
    new_state["selected_rows"] = (
        int(state["selected_rows"]) + selected_delta
    )
    new_state["eof"] = eof
    new_state["slices"] = [*state["slices"], slice_row]
    _atomic_json(member_dir / "state.json", new_state)
    return new_state, processed_nonblank


def _finalize_member(
    *,
    member_dir: Path,
    state: dict[str, Any],
    work_dir: Path,
    resumable,
) -> dict[str, Any]:
    if not state.get("eof"):
        raise SlicedNormalizationError("cannot finalize before EOF")

    raw_path = member_dir / "source.jsonl"
    if _sha256(raw_path) != state["raw_sha256"]:
        raise SlicedNormalizationError(
            f"raw-cache hash mismatch before finalization: "
            f"{state['source_name']}"
        )

    index = int(state["index"])
    corpus_chunk, identity_chunk, marker_path = resumable._paths(
        work_dir,
        index,
    )
    if marker_path.exists():
        raise SlicedNormalizationError(
            f"marker unexpectedly exists before sliced finalization: "
            f"{marker_path}"
        )
    corpus_tmp = work_dir / f"{index:06d}.corpus.sliced-final.tmp"
    identity_tmp = work_dir / f"{index:06d}.identity.sliced-final.tmp"
    marker_tmp = work_dir / f"{index:06d}.done.sliced-final.tmp"
    for path in (corpus_tmp, identity_tmp, marker_tmp):
        path.unlink(missing_ok=True)

    with (
        corpus_tmp.open("wb") as corpus_out,
        identity_tmp.open("wb") as identity_out,
    ):
        for row in state["slices"]:
            number = int(row["number"])
            corpus = member_dir / f"slice-{number:06d}.corpus"
            identity = member_dir / f"slice-{number:06d}.identity"
            if _sha256(corpus) != row["corpus_sha256"]:
                raise SlicedNormalizationError(
                    f"corpus slice changed before finalization: {number}"
                )
            if _sha256(identity) != row["identity_sha256"]:
                raise SlicedNormalizationError(
                    f"identity slice changed before finalization: {number}"
                )
            with corpus.open("rb") as src:
                shutil.copyfileobj(src, corpus_out, 1024 * 1024)
            with identity.open("rb") as src:
                shutil.copyfileobj(src, identity_out, 1024 * 1024)

        corpus_out.flush()
        identity_out.flush()
        os.fsync(corpus_out.fileno())
        os.fsync(identity_out.fileno())

    corpus_sha = _sha256(corpus_tmp)
    identity_sha = _sha256(identity_tmp)
    corpus_size = corpus_tmp.stat().st_size
    identity_size = identity_tmp.stat().st_size
    os.replace(corpus_tmp, corpus_chunk)
    os.replace(identity_tmp, identity_chunk)

    marker = {
        **resumable._marker_contract(
            index=index,
            source_name=str(state["source_name"]),
            source_file_size=int(state["source_file_size"]),
            start=str(state["start"]),
            end=str(state["end"]),
        ),
        "source_rows": int(state["source_rows"]),
        "outside_window_rows": int(state["outside_window_rows"]),
        "selected_rows": int(state["selected_rows"]),
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

    shutil.rmtree(member_dir)
    return marker


def advance(
    *,
    source: Path,
    adapter_path: Path,
    resumable_path: Path,
    work_dir: Path,
    slice_root: Path,
    start: str,
    end: str,
    max_seconds: float,
    max_rows: int,
    backend: str,
    orjson_root: Path,
    seven_zip: Path | None,
) -> dict[str, Any]:
    if max_seconds <= 5:
        raise SlicedNormalizationError("--max-seconds must be > 5")
    if max_rows < 1:
        raise SlicedNormalizationError("--max-rows must be >= 1")

    source = source.resolve()
    adapter_path = adapter_path.resolve()
    resumable_path = resumable_path.resolve()
    work_dir = work_dir.resolve()
    slice_root = slice_root.resolve()
    adapter = _load_module(adapter_path, "p2_37_sliced_adapter")
    resumable = _load_module(
        resumable_path,
        "p2_37_sliced_resumable_authority",
    )
    if _git_blob_sha1(adapter_path) != EXPECTED_ADAPTER_GIT_BLOB_SHA1:
        raise SlicedNormalizationError(
            "frozen adapter Git blob SHA-1 mismatch"
        )
    if (
        resumable.EXPECTED_ADAPTER_GIT_BLOB_SHA1
        != EXPECTED_ADAPTER_GIT_BLOB_SHA1
    ):
        raise SlicedNormalizationError(
            "resumable normalizer adapter pin mismatch"
        )

    orjson_module = None
    if backend == "orjson":
        sys.path.insert(0, str(orjson_root.resolve()))
        try:
            import orjson as imported_orjson
        except Exception as exc:
            raise SlicedNormalizationError(
                f"unable to import orjson: {exc}"
            ) from exc
        orjson_module = imported_orjson

    if seven_zip is not None:
        seven_zip = seven_zip.resolve()
        if not seven_zip.is_file():
            raise SlicedNormalizationError(
                f"7-Zip executable not found: {seven_zip}"
            )

    start_dt, end_dt = adapter._window(start, end)
    source_names = adapter._winlogbeat_source_names(source)
    with zipfile.ZipFile(source) as archive:
        by_name = {info.filename: info for info in archive.infolist()}
        source_sizes = {
            name: int(by_name[name].file_size)
            for name in source_names
        }

    work_dir.mkdir(parents=True, exist_ok=True)
    slice_root.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + max_seconds
    rows_this_invocation = 0
    finalized: list[int] = []

    for index, source_name in enumerate(source_names):
        marker = resumable._read_valid_marker(
            work_dir=work_dir,
            index=index,
            source_name=source_name,
            source_file_size=source_sizes[source_name],
            start=start,
            end=end,
        )
        if marker is not None:
            member_dir = _member_dir(slice_root, index)
            if member_dir.exists():
                shutil.rmtree(member_dir)
            continue

        member_dir = _member_dir(slice_root, index)
        state = _load_state(
            member_dir=member_dir,
            index=index,
            source_name=source_name,
            source_file_size=source_sizes[source_name],
            start=start,
            end=end,
        )
        if state is None:
            if time.monotonic() >= deadline - 5:
                break
            raw_size, raw_sha = _extract_raw(
                source=source,
                source_name=source_name,
                member_dir=member_dir,
                seven_zip=seven_zip,
            )
            state = _new_state(
                index=index,
                source_name=source_name,
                source_file_size=source_sizes[source_name],
                start=start,
                end=end,
                raw_size=raw_size,
                raw_sha256=raw_sha,
            )
            _atomic_json(member_dir / "state.json", state)

        if state.get("eof"):
            marker = _finalize_member(
                member_dir=member_dir,
                state=state,
                work_dir=work_dir,
                resumable=resumable,
            )
            finalized.append(index)
            print(
                f"FINALIZED index={index} "
                f"selected_rows={marker['selected_rows']}",
                flush=True,
            )
            if time.monotonic() >= deadline - 5:
                break
            continue

        remaining_rows = max_rows - rows_this_invocation
        if remaining_rows <= 0 or time.monotonic() >= deadline:
            break

        state, processed = _process_slice(
            member_dir=member_dir,
            state=state,
            adapter=adapter,
            start_dt=start_dt,
            end_dt=end_dt,
            backend=backend,
            orjson_module=orjson_module,
            max_rows=remaining_rows,
            deadline=deadline,
        )
        rows_this_invocation += processed
        print(
            f"SLICE index={index} processed_rows={processed} "
            f"next_line={state['next_line_number']} "
            f"eof={state['eof']}",
            flush=True,
        )

        if state.get("eof") and time.monotonic() < deadline - 10:
            marker = _finalize_member(
                member_dir=member_dir,
                state=state,
                work_dir=work_dir,
                resumable=resumable,
            )
            finalized.append(index)
            print(
                f"FINALIZED index={index} "
                f"selected_rows={marker['selected_rows']}",
                flush=True,
            )

        if rows_this_invocation >= max_rows:
            break
        if time.monotonic() >= deadline - 5:
            break
        if not state.get("eof"):
            break

    committed = len(list(work_dir.glob("*.done.json")))
    result = {
        "status": "PASS",
        "detection_rules_executed": False,
        "labels_read": False,
        "committed_members": committed,
        "total_members": len(source_names),
        "rows_processed_this_invocation": rows_this_invocation,
        "members_finalized_this_invocation": finalized,
        "elapsed_seconds": time.monotonic() - started,
        "max_seconds": max_seconds,
        "max_rows": max_rows,
        "json_backend": backend,
        "seven_zip_enabled": seven_zip is not None,
        "frozen_adapter_git_blob_sha1": EXPECTED_ADAPTER_GIT_BLOB_SHA1,
    }
    return result


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--winlogbeat-root", required=True)
    ap.add_argument("--adapter", required=True)
    ap.add_argument("--resumable-normalizer", required=True)
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--slice-root", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--max-seconds", type=float, default=75.0)
    ap.add_argument("--max-rows", type=int, default=150000)
    ap.add_argument(
        "--json-backend",
        choices=("stdlib", "orjson"),
        default="stdlib",
    )
    ap.add_argument("--orjson-root", default=".")
    ap.add_argument("--seven-zip", default="")
    return ap


def main() -> int:
    args = parser().parse_args()
    result = advance(
        source=Path(args.winlogbeat_root),
        adapter_path=Path(args.adapter),
        resumable_path=Path(args.resumable_normalizer),
        work_dir=Path(args.work_dir),
        slice_root=Path(args.slice_root),
        start=args.start,
        end=args.end,
        max_seconds=args.max_seconds,
        max_rows=args.max_rows,
        backend=args.json_backend,
        orjson_root=Path(args.orjson_root),
        seven_zip=Path(args.seven_zip) if args.seven_zip else None,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
