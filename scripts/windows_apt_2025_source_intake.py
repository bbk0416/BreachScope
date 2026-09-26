from __future__ import annotations

import argparse
import csv
import hashlib
import json
import ntpath
import re
import zipfile
from pathlib import Path
from typing import Any


SCHEMA = "breachscope.windows_apt_2025_source_intake.v1"
ANALYSIS_ID = "windows-apt-2025-v3-source-intake-v1"
DATASET_ID = "b8fmtzvpy8"
DATASET_VERSION = 3
DOWNLOAD_ENDPOINT = (
    "https://data.mendeley.com/public-api/zip/"
    "b8fmtzvpy8/download/3"
)
EXPECTED_COMBINED = "combined.csv"
EXPECTED_SUPPLEMENTARY = {
    "scenario_manifest.csv",
    "validation_summary.csv",
}
SOURCE_INTENT_TOKENS = {
    "label",
    "class",
    "malicious",
    "benign",
    "intent",
    "sourceintent",
    "groundtruth",
}


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_member(zf: zipfile.ZipFile, member: str) -> str:
    h = hashlib.sha256()
    with zf.open(member) as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalise_checksum_name(raw_path: str) -> str:
    return ntpath.basename(raw_path.strip())


def _parse_checksums(text: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"invalid checksum line: {raw!r}")
        digest, path = parts
        name = _normalise_checksum_name(path.lstrip("*"))
        rows[name] = digest.lower()
    return rows


def _header_metadata(zf: zipfile.ZipFile, member: str) -> dict[str, Any]:
    with zf.open(member) as f:
        first = f.readline()
        if not first:
            raise ValueError(f"empty CSV: {member}")

        bom = first.startswith(b"\xef\xbb\xbf")
        encoding = "utf-8-sig" if bom else "utf-8"
        try:
            header = first.decode(encoding).rstrip("\r\n")
        except UnicodeDecodeError as exc:
            raise ValueError(f"CSV header is not UTF-8: {member}") from exc

        try:
            columns = next(csv.reader([header]))
        except csv.Error as exc:
            raise ValueError(f"cannot parse CSV header: {member}") from exc

        remaining_newlines = 0
        remaining_any = False
        last_byte = b""
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            remaining_any = True
            remaining_newlines += chunk.count(b"\n")
            last_byte = chunk[-1:]

    physical_data_lines = remaining_newlines
    if remaining_any and last_byte != b"\n":
        physical_data_lines += 1

    explicit_candidates: list[str] = []
    for column in columns:
        compact = re.sub(r"[^a-z0-9]+", "", column.lower())
        tokens = {
            token
            for token in re.split(r"[^a-z0-9]+", column.lower())
            if token
        }
        if compact in SOURCE_INTENT_TOKENS or tokens & SOURCE_INTENT_TOKENS:
            explicit_candidates.append(column)

    return {
        "encoding": encoding,
        "bom": bom,
        "delimiter": ",",
        "header": header,
        "columns": columns,
        "column_count": len(columns),
        "physical_data_lines_after_header": physical_data_lines,
        "physical_line_count_is_not_logical_csv_record_count": True,
        "explicit_source_intent_header_candidates": explicit_candidates,
    }


def inspect_archive(
    archive_path: Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
) -> dict[str, Any]:
    archive_path = archive_path.resolve()
    actual_size = archive_path.stat().st_size
    actual_sha256 = _sha256_path(archive_path)

    if actual_size != expected_size_bytes:
        raise ValueError(
            f"archive size mismatch: {actual_size} != {expected_size_bytes}"
        )
    if actual_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            f"archive sha256 mismatch: {actual_sha256} != {expected_sha256}"
        )

    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        members = [info.filename for info in infos]
        checksum_members = [
            name for name in members if name.endswith("checksums.sha256")
        ]
        if len(checksum_members) != 1:
            raise ValueError(
                f"expected exactly one checksums.sha256, got {checksum_members}"
            )
        checksum_member = checksum_members[0]
        root_prefix = checksum_member[: -len("checksums.sha256")]

        csv_infos = [
            info
            for info in infos
            if info.filename.startswith(root_prefix)
            and info.filename.lower().endswith(".csv")
        ]
        csv_names = sorted(
            info.filename[len(root_prefix) :] for info in csv_infos
        )
        if len(csv_names) != 19:
            raise ValueError(f"expected 19 CSV files, got {len(csv_names)}")
        if EXPECTED_COMBINED not in csv_names:
            raise ValueError("combined.csv is missing")
        if not EXPECTED_SUPPLEMENTARY.issubset(csv_names):
            raise ValueError("supplementary CSV files are missing")

        per_period = sorted(
            name
            for name in csv_names
            if name != EXPECTED_COMBINED
            and name not in EXPECTED_SUPPLEMENTARY
        )
        if len(per_period) != 16:
            raise ValueError(
                f"expected 16 per-period CSV files, got {len(per_period)}"
            )

        checksum_text = zf.read(checksum_member).decode("utf-8")
        expected_checksums = _parse_checksums(checksum_text)
        if set(expected_checksums) != set(csv_names):
            raise ValueError(
                "bundled checksum names do not exactly match the 19 CSV members"
            )

        csv_rows: list[dict[str, Any]] = []
        matched = 0
        for name in csv_names:
            member = root_prefix + name
            actual_member_sha = _sha256_member(zf, member)
            expected_member_sha = expected_checksums[name]
            checksum_match = actual_member_sha == expected_member_sha
            matched += int(checksum_match)
            header = _header_metadata(zf, member)
            info = zf.getinfo(member)
            csv_rows.append(
                {
                    "name": name,
                    "archive_member": member,
                    "size_bytes": info.file_size,
                    "compressed_size_bytes": info.compress_size,
                    "crc32": f"{info.CRC:08x}",
                    "sha256": actual_member_sha,
                    "bundled_sha256": expected_member_sha,
                    "bundled_sha256_match": checksum_match,
                    **header,
                }
            )

        if matched != len(csv_rows):
            raise ValueError(
                f"bundled checksum mismatch: {matched}/{len(csv_rows)} matched"
            )

        documentation_names = [
            "README.md",
            "scripts/load_and_merge_logs.py",
            "scripts/parse_attack_mapping_and_filter.py",
        ]
        documentation: list[dict[str, Any]] = []
        for name in documentation_names:
            member = root_prefix + name
            if member not in members:
                raise ValueError(f"missing documented support file: {name}")
            info = zf.getinfo(member)
            documentation.append(
                {
                    "name": name,
                    "archive_member": member,
                    "size_bytes": info.file_size,
                    "sha256": _sha256_member(zf, member),
                }
            )

        inventory = [
            {
                "path": info.filename,
                "size_bytes": info.file_size,
                "compressed_size_bytes": info.compress_size,
                "crc32": f"{info.CRC:08x}",
            }
            for info in infos
        ]

    label_candidates = {
        row["name"]: row["explicit_source_intent_header_candidates"]
        for row in csv_rows
        if row["explicit_source_intent_header_candidates"]
    }

    return {
        "schema": SCHEMA,
        "analysis_id": ANALYSIS_ID,
        "status": "COMPLETED_METADATA_ONLY",
        "source": {
            "provider": "Mendeley Data",
            "dataset_id": DATASET_ID,
            "version": DATASET_VERSION,
            "download_endpoint": DOWNLOAD_ENDPOINT,
            "archive_size_bytes": actual_size,
            "archive_sha256": actual_sha256,
        },
        "protocol": {
            "semantic_data_rows_decoded_or_printed": False,
            "semantic_data_rows_parsed_as_csv_records": False,
            "detector_rules_executed_against_source": False,
            "csv_access_scope": (
                "header line only plus opaque byte streaming for SHA-256 "
                "and physical newline counts"
            ),
            "documentation_text_review_allowed": True,
        },
        "package": {
            "root_prefix": root_prefix,
            "member_count": len(inventory),
            "total_uncompressed_bytes": sum(
                row["size_bytes"] for row in inventory
            ),
            "total_compressed_member_bytes": sum(
                row["compressed_size_bytes"] for row in inventory
            ),
            "inventory": inventory,
        },
        "integrity": {
            "checksum_member": checksum_member,
            "checksum_entry_count": len(expected_checksums),
            "csv_checksum_match_count": matched,
            "csv_checksum_total": len(csv_rows),
            "all_csv_checksums_match": matched == len(csv_rows),
        },
        "selection": {
            "selected_event_files": per_period,
            "selected_event_file_count": len(per_period),
            "excluded_duplicate_event_file": EXPECTED_COMBINED,
            "excluded_supplementary_csvs": sorted(EXPECTED_SUPPLEMENTARY),
            "selection_rule": (
                "all CSV members except combined.csv, "
                "scenario_manifest.csv, and validation_summary.csv"
            ),
            "posthoc_subsetting_allowed": False,
        },
        "csv_files": csv_rows,
        "documentation": documentation,
        "label_provenance_probe": {
            "explicit_source_intent_header_candidates": label_candidates,
            "candidate_count": sum(len(v) for v in label_candidates.values()),
            "attack_mitre_fields_are_not_source_intent_labels": True,
            "semantic_rows_inspected_to_find_labels": False,
        },
        "claim_boundary": {
            "event_level_attack_ground_truth": "NOT_ESTABLISHED",
            "event_level_benign_ground_truth": "NOT_ESTABLISHED",
            "confirmed_false_positive_rate": "NOT_CLAIMED",
            "event_level_recall": "NOT_CLAIMED",
            "production_accuracy": "NOT_CLAIMED",
            "production_recall": "NOT_CLAIMED",
            "production_false_positive_rate": "NOT_CLAIMED",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-size-bytes", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    result = inspect_archive(
        Path(args.archive),
        expected_sha256=args.expected_sha256,
        expected_size_bytes=args.expected_size_bytes,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "archive_sha256": result["source"]["archive_sha256"],
                "archive_size_bytes": result["source"]["archive_size_bytes"],
                "member_count": result["package"]["member_count"],
                "csv_count": len(result["csv_files"]),
                "selected_event_file_count": result["selection"][
                    "selected_event_file_count"
                ],
                "checksum_match_count": result["integrity"][
                    "csv_checksum_match_count"
                ],
                "label_candidate_count": result["label_provenance_probe"][
                    "candidate_count"
                ],
                "output": str(output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())