from __future__ import annotations

import argparse
import json
from pathlib import Path

EXPECTED_ARCHIVE_SHA256 = "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
SCHEMA = "breachscope.p2_13b_win11_benign_binding.v4"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--shards", type=int, required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

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
        "source_shard_run_id": 34680672963,
        "source_shard_head_sha": "6efb3d17262effa7dffefad9ffcac8707f6bf4c7",
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "note": "Recovered aggregate from the 16 successful chunk-shard artifacts of run 34680672963 after its aggregate job failed only because the aggregate runner lacked python-evtx. No BreachScope detector execution occurred in P2-13B."
        },
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
