from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from Evtx.Evtx import Evtx

EXPECTED_ARCHIVE_SHA256 = "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
SCHEMA = "breachscope.p2_13b_win11_benign_binding.v3"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_provider_and_event_id(xml_text: str) -> tuple[str, str]:
    root = ET.fromstring(xml_text)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    provider = root.find("e:System/e:Provider", ns)
    event_id = root.find("e:System/e:EventID", ns)
    return (
        (provider.attrib.get("Name", "") if provider is not None else ""),
        (event_id.text or "" if event_id is not None else ""),
    )


def run_shard(args: argparse.Namespace) -> int:
    archive = Path(args.archive)
    extracted = Path(args.extracted)
    archive_sha = sha256_file(archive)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise SystemExit(f"archive sha mismatch: {archive_sha}")

    files = sorted(p for p in extracted.rglob("*.evtx") if p.is_file())
    selected = [p for i, p in enumerate(files) if i % args.shards == args.shard]

    total_records = 0
    sysmon_records = 0
    sysmon_event1 = 0
    parse_errors = 0
    per_file = []

    for path in selected:
        file_records = 0
        file_sysmon = 0
        file_sysmon_event1 = 0
        file_errors = 0
        try:
            with Evtx(str(path)) as evtx:
                for record in evtx.records():
                    total_records += 1
                    file_records += 1
                    try:
                        provider, event_id = parse_provider_and_event_id(record.xml())
                    except Exception:
                        parse_errors += 1
                        file_errors += 1
                        continue
                    if provider == "Microsoft-Windows-Sysmon":
                        sysmon_records += 1
                        file_sysmon += 1
                        if event_id == "1":
                            sysmon_event1 += 1
                            file_sysmon_event1 += 1
        except Exception:
            parse_errors += 1
            file_errors += 1
        per_file.append(
            {
                "path": str(path.relative_to(extracted)).replace("\\", "/"),
                "records": file_records,
                "sysmon_records": file_sysmon,
                "sysmon_event1": file_sysmon_event1,
                "parse_errors": file_errors,
            }
        )

    out = {
        "schema": SCHEMA,
        "mode": "shard",
        "archive_sha256": archive_sha,
        "shard": args.shard,
        "shards": args.shards,
        "all_evtx_files": len(files),
        "selected_evtx_files": len(selected),
        "total_records": total_records,
        "sysmon_records": sysmon_records,
        "sysmon_event1": sysmon_event1,
        "parse_errors": parse_errors,
        "detector_imported": False,
        "detector_executed": False,
        "files": per_file,
    }
    Path(args.output).write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("shard", "selected_evtx_files", "total_records", "sysmon_records", "sysmon_event1", "parse_errors")}, sort_keys=True))
    return 0


def run_aggregate(args: argparse.Namespace) -> int:
    inputs = sorted(Path(args.inputs).glob("shard-*.json"))
    if len(inputs) != args.shards:
        raise SystemExit(f"expected {args.shards} shard files, got {len(inputs)}")
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in inputs]
    rows.sort(key=lambda r: r["shard"])
    assert [r["shard"] for r in rows] == list(range(args.shards))
    assert all(r["schema"] == SCHEMA for r in rows)
    assert all(r["archive_sha256"] == EXPECTED_ARCHIVE_SHA256 for r in rows)
    assert all(r["shards"] == args.shards for r in rows)
    assert all(r["detector_imported"] is False and r["detector_executed"] is False for r in rows)
    all_counts = {r["all_evtx_files"] for r in rows}
    if len(all_counts) != 1:
        raise SystemExit(f"shards disagree on all_evtx_files: {all_counts}")
    all_evtx_files = next(iter(all_counts))
    paths = [f["path"] for r in rows for f in r["files"]]
    if len(paths) != len(set(paths)):
        raise SystemExit("duplicate EVTX paths across shards")
    if len(paths) != all_evtx_files:
        raise SystemExit(f"coverage mismatch: {len(paths)} != {all_evtx_files}")

    result = {
        "schema": SCHEMA,
        "mode": "aggregate",
        "source_repository": "NextronSystems/evtx-baseline",
        "release": "v0.8.4",
        "asset": "win11-client-2023.tgz",
        "asset_id": 371539645,
        "archive_size_bytes": 169460461,
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "evtx_files": all_evtx_files,
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
            "note": "Byte/inventory binding only. No BreachScope detector execution occurred in P2-13B.",
        },
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("shard")
    s.add_argument("--archive", required=True)
    s.add_argument("--extracted", required=True)
    s.add_argument("--shard", type=int, required=True)
    s.add_argument("--shards", type=int, required=True)
    s.add_argument("--output", required=True)
    a = sub.add_parser("aggregate")
    a.add_argument("--inputs", required=True)
    a.add_argument("--shards", type=int, required=True)
    a.add_argument("--output", required=True)
    args = ap.parse_args()
    return run_shard(args) if args.cmd == "shard" else run_aggregate(args)


if __name__ == "__main__":
    raise SystemExit(main())
