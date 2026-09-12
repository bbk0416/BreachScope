from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from Evtx.Evtx import Evtx


EXPECTED_SHA256 = "739079e63fc8a81d0b20eff6ee76b2f104a0cf6df115802c9bca128417c1e117"
EXPECTED_ASSET_SIZE = 169460461


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: p2_13b_bind_win11_benign.py ARCHIVE EXTRACTED_ROOT OUTPUT_JSON")

    archive = Path(sys.argv[1])
    root = Path(sys.argv[2])
    out = Path(sys.argv[3])

    assert archive.is_file(), archive
    assert archive.stat().st_size == EXPECTED_ASSET_SIZE, archive.stat().st_size
    archive_sha = sha256_file(archive)
    assert archive_sha == EXPECTED_SHA256, (archive_sha, EXPECTED_SHA256)

    evtx_files = sorted(p for p in root.rglob("*.evtx") if p.is_file())
    assert evtx_files, "no EVTX files extracted"

    total_records = 0
    sysmon_records = 0
    parse_errors = 0
    per_file = []

    for path in evtx_files:
        count = 0
        file_errors = 0
        is_sysmon = "sysmon" in path.name.lower() or "sysmon" in str(path.parent).lower()
        try:
            with Evtx(str(path)) as log:
                for record in log.records():
                    count += 1
                    try:
                        record.xml()
                    except Exception:
                        file_errors += 1
        except Exception:
            file_errors += 1

        total_records += count
        parse_errors += file_errors
        if is_sysmon:
            sysmon_records += count
        per_file.append(
            {
                "path": path.relative_to(root).as_posix(),
                "records": count,
                "parse_errors": file_errors,
                "sysmon_by_path": is_sysmon,
            }
        )

    result = {
        "schema": "breachscope.p2_13b_win11_benign_binding.v1",
        "binding_class": "fresh_benign_by_source_intent_byte_binding",
        "source": {
            "repository": "NextronSystems/evtx-baseline",
            "release_tag": "v0.8.4",
            "asset_name": "win11-client-2023.tgz",
            "asset_id": 371539645,
            "asset_size_bytes": archive.stat().st_size,
            "archive_sha256": archive_sha,
        },
        "inventory": {
            "evtx_file_count": len(evtx_files),
            "total_records": total_records,
            "sysmon_records_by_path": sysmon_records,
            "parse_errors": parse_errors,
        },
        "per_file": per_file,
        "protocol": {
            "detector_imported": False,
            "detector_executed": False,
            "detector_results_consulted": False,
        },
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "production_precision": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "note": "This stage binds bytes and inventories a fresh public benign-by-source-intent corpus before any BreachScope detector execution.",
        },
    }

    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["inventory"], indent=2, sort_keys=True))
    print(f"P2_13B_ARCHIVE_SHA256={archive_sha}")
    print("P2_13B_DETECTOR_EXECUTED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
