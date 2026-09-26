from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows_apt_2025_source_intake.py"

_spec = importlib.util.spec_from_file_location("windows_apt_intake", SCRIPT)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
inspect_archive = _module.inspect_archive


PERIOD_FILES = [
    "01-03-December.csv",
    "03-04-December.csv",
    "04-07-December.csv",
    "07-10-December.csv",
    "1-11-November.csv",
    "10-December-P1.csv",
    "10-December-P2.csv",
    "11-12-December.csv",
    "11-16-November.csv",
    "12-13-December.csv",
    "13-14-December.csv",
    "14-17-December.csv",
    "22-December.csv",
    "23-30-November.csv",
    "28-October-01-November.csv",
    "30-November.csv",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_archive(
    tmp_path: Path,
    *,
    corrupt_checksum: bool = False,
    add_label_header: bool = False,
) -> Path:
    root = "Windows-APT 2025 A Dataset for APT-Inspired Attack/"
    archive = tmp_path / "windows-apt-v3.zip"
    payloads: dict[str, bytes] = {}

    for index, name in enumerate(PERIOD_FILES):
        header = "timestamp,label\n" if add_label_header and index == 0 else "timestamp,event\n"
        payloads[name] = (
            header + f"2026-01-01T00:00:00Z,SECRET_SEMANTIC_ROW_{index}\n"
        ).encode("utf-8")

    payloads["combined.csv"] = (
        "\ufefftimestamp,event\n"
        "2026-01-01T00:00:00Z,SECRET_COMBINED_ROW\n"
    ).encode("utf-8")
    payloads["scenario_manifest.csv"] = (
        "Scenrario_ID,Scenario_Name\n"
        "1,SECRET_SCENARIO_NAME\n"
    ).encode("utf-8")
    payloads["validation_summary.csv"] = (
        "Scenrario_ID,Scenario_Name\n"
        "1,SECRET_VALIDATION_NAME\n"
    ).encode("utf-8")

    checksum_lines = []
    for name, data in sorted(payloads.items()):
        digest = _sha(data)
        if corrupt_checksum and name == PERIOD_FILES[0]:
            digest = "0" * 64
        checksum_lines.append(
            f"{digest.upper()}  E:\\Window-APT2025\\wazuh-logs\\{name}"
        )

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in payloads.items():
            zf.writestr(root + name, data)
        zf.writestr(
            root + "checksums.sha256",
            ("\n\n".join(checksum_lines) + "\n").encode("utf-8"),
        )
        zf.writestr(root + "README.md", b"# synthetic metadata only\n")
        zf.writestr(
            root + "scripts/load_and_merge_logs.py",
            b"# synthetic helper\n",
        )
        zf.writestr(
            root + "scripts/parse_attack_mapping_and_filter.py",
            b"# synthetic helper\n",
        )

    return archive


def _inspect(archive: Path) -> dict:
    return inspect_archive(
        archive,
        expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        expected_size_bytes=archive.stat().st_size,
    )


def test_windows_apt_intake_records_metadata_without_semantic_rows(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path)
    result = _inspect(archive)

    assert result["status"] == "COMPLETED_METADATA_ONLY"
    assert result["protocol"]["semantic_data_rows_decoded_or_printed"] is False
    assert result["protocol"]["semantic_data_rows_parsed_as_csv_records"] is False
    assert result["protocol"]["detector_rules_executed_against_source"] is False

    assert result["package"]["member_count"] == 23
    assert result["integrity"]["csv_checksum_match_count"] == 19
    assert result["integrity"]["all_csv_checksums_match"] is True
    assert result["selection"]["selected_event_file_count"] == 16
    assert result["selection"]["selected_event_files"] == sorted(PERIOD_FILES)
    assert result["selection"]["excluded_duplicate_event_file"] == "combined.csv"
    assert result["label_provenance_probe"]["candidate_count"] == 0

    by_name = {row["name"]: row for row in result["csv_files"]}
    assert by_name["01-03-December.csv"]["header"] == "timestamp,event"
    assert by_name["01-03-December.csv"]["physical_data_lines_after_header"] == 1
    assert by_name["combined.csv"]["encoding"] == "utf-8-sig"
    assert by_name["combined.csv"]["bom"] is True

    serialized = json.dumps(result)
    assert "SECRET_SEMANTIC_ROW" not in serialized
    assert "SECRET_COMBINED_ROW" not in serialized
    assert "SECRET_SCENARIO_NAME" not in serialized
    assert "SECRET_VALIDATION_NAME" not in serialized


def test_windows_apt_intake_rejects_bundled_checksum_mismatch(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path, corrupt_checksum=True)

    with pytest.raises(ValueError, match="bundled checksum mismatch"):
        _inspect(archive)


def test_windows_apt_intake_detects_explicit_label_header_without_reading_rows(
    tmp_path: Path,
) -> None:
    archive = _make_archive(tmp_path, add_label_header=True)
    result = _inspect(archive)

    candidates = result["label_provenance_probe"][
        "explicit_source_intent_header_candidates"
    ]
    assert candidates["01-03-December.csv"] == ["label"]
    assert result["label_provenance_probe"]["candidate_count"] == 1
    assert "SECRET_SEMANTIC_ROW" not in json.dumps(result)
