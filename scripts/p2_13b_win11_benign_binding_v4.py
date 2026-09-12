from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

EXPECTED_ARCHIVE_SHA256 = "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
SCHEMA = "breachscope.p2_13b_win11_benign_binding.v4"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def event_identity(xml_text: str) -> tuple[str, str]:
    root = ET.fromstring(xml_text)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    provider = root.find("e:System/e:Provider", ns)
    event_id = root.find("e:System/e:EventID", ns)
    return (
        provider.attrib.get("Name", "") if provider is not None else "",
        (event_id.text or "") if event_id is not None else "",
    )


def enumerate_chunks(root: Path) -> tuple[list[Path], list[tuple[Path, int, object]]]:
    files = sorted(p for p in root.rglob("*.evtx") if p.is_file())
    chunks: list[tuple[Path, int, object]] = []
    # Chunk objects are tied to an open Evtx context, so this helper is only used
    # for file discovery. Actual chunks are enumerated during parsing below.
    return files, chunks


def run_shard(args: argparse.Namespace) -> int:
    archive = Path(args.archive)
    root = Path(args.extracted)
    archive_sha = sha256_file(archive)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise SystemExit(f"archive SHA mismatch: {archive_sha}")

    files = sorted(p for p in root.rglob("*.evtx") if p.is_file())
    total_chunks = 0
    selected_chunks = 0
    total_records = 0
    sysmon_records = 0
    sysmon_event1 = 0
    parse_errors = 0
    chunk_ids: list[str] = []

    # First pass: all shards independently establish the same total chunk count.
    per_file_chunk_counts: list[tuple[Path, int]] = []
    for path in files:
        try:
            with Evtx(str(path)) as evtx:
                n = sum(1 for _ in evtx.chunks())
        except Exception as exc:
            raise SystemExit(f"failed to enumerate chunks in {path}: {exc}")
        per_file_chunk_counts.append((path, n))
        total_chunks += n

    global_chunk_index = 0
    for path, expected_chunks in per_file_chunk_counts:
        seen = 0
        with Evtx(str(path)) as evtx:
            for local_index, chunk in enumerate(evtx.chunks()):
                seen += 1
                assigned = global_chunk_index % args.shards == args.shard
                if assigned:
                    selected_chunks += 1
                    rel = str(path.relative_to(root)).replace("\\", "/")
                    chunk_ids.append(f"{rel}#{local_index}")
                    try:
                        records = chunk.records()
                        for record in records:
                            total_records += 1
                            try:
                                provider, event_id = event_identity(record.xml())
                            except Exception:
                                parse_errors += 1
                                continue
                            if provider == "Microsoft-Windows-Sysmon":
                                sysmon_records += 1
                                if event_id == "1":
                                    sysmon_event1 += 1
                    except Exception:
                        parse_errors += 1
                global_chunk_index += 1
        if seen != expected_chunks:
            raise SystemExit(f"chunk enumeration drift for {path}: {seen} != {expected_chunks}")

    if global_chunk_index != total_chunks:
        raise SystemExit(f"global chunk drift: {global_chunk_index} != {total_chunks}")

    out = {
        "schema": SCHEMA,
        "mode": "shard",
        "archive_sha256": archive_sha,
        "shard": args.shard,
        "shards": args.shards,
        "evtx_files": len(files),
        "total_chunks": total_chunks,
        "selected_chunks": selected_chunks,
        "chunk_ids": chunk_ids,
        "total_records": total_records,
        "sysmon_records": sysmon_records,
        "sysmon_event1": sysmon_event1,
        "parse_errors": parse_errors,
        "detector_imported": False,
        "detector_executed": False,
    }
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("shard", "selected_chunks", "total_records", "sysmon_records", "sysmon_event1", "parse_errors")}, sort_keys=True))
    return 0


def run_aggregate(args: argparse.Namespace) -> int:
    paths = sorted(Path(args.inputs).glob("shard-*.json"))
    if len(paths) != args.shards:
        raise SystemExit(f"expected {args.shards} shard files, got {len(paths)}")
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    rows.sort(key=lambda r: r["shard"])
    assert [r["shard"] for r in rows] == list(range(args.shards))
    assert all(r["schema"] == SCHEMA for r in rows)
    assert all(r["archive_sha256"] == EXPECTED_ARCHIVE_SHA256 for r in rows)
    assert all(r["shards"] == args.shards for r in rows)
    assert all(r["detector_imported"] is False and r["detector_executed"] is False for r in rows)

    evtx_counts = {r["evtx_files"] for r in rows}
    chunk_counts = {r["total_chunks"] for r in rows}
    if len(evtx_counts) != 1 or len(chunk_counts) != 1:
        raise SystemExit(f"shards disagree: evtx={evtx_counts}, chunks={chunk_counts}")
    evtx_files = next(iter(evtx_counts))
    total_chunks = next(iter(chunk_counts))
    chunk_ids = [cid for r in rows for cid in r["chunk_ids"]]
    if len(chunk_ids) != len(set(chunk_ids)):
        raise SystemExit("duplicate chunk IDs across shards")
    if len(chunk_ids) != total_chunks:
        raise SystemExit(f"chunk coverage mismatch: {len(chunk_ids)} != {total_chunks}")
    if sum(r["selected_chunks"] for r in rows) != total_chunks:
        raise SystemExit("selected chunk count mismatch")

    result = {
        "schema": SCHEMA,
        "mode": "aggregate",
        "source_repository": "NextronSystems/evtx-baseline",
        "release": "v0.8.4",
        "asset": "win11-client-2023.tgz",
        "asset_id": 371539645,
        "archive_size_bytes": 169460461,
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "evtx_files": evtx_files,
        "evtx_chunks": total_chunks,
        "total_records": sum(r["total_records"] for r in rows),
        "sysmon_records": sum(r["sysmon_records"] for r in rows),
        "sysmon_event1": sum(r["sysmon_event1"] for r in rows),
        "parse_errors": sum(r["parse_errors"] for r in rows),
        "detector_imported": False,
        "detector_executed": False,
        "results_consulted": False,
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "note": "Byte/inventory binding only. Every discovered EVTX chunk is covered exactly once across shards. No BreachScope detector execution occurred in P2-13B.",
        },
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("shard")
    sp.add_argument("--archive", required=True)
    sp.add_argument("--extracted", required=True)
    sp.add_argument("--shard", type=int, required=True)
    sp.add_argument("--shards", type=int, required=True)
    sp.add_argument("--output", required=True)
    ag = sub.add_parser("aggregate")
    ag.add_argument("--inputs", required=True)
    ag.add_argument("--shards", type=int, required=True)
    ag.add_argument("--output", required=True)
    args = ap.parse_args()
    return run_shard(args) if args.cmd == "shard" else run_aggregate(args)


if __name__ == "__main__":
    raise SystemExit(main())
