from __future__ import annotations

import bz2
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "p2_37_verify_dedale_window_sentinels.py"
ADAPTER = ROOT / "scripts" / "p2_37_prepare_dedale_holdout.py"
AMENDMENT = ROOT / "external_baseline" / "p2_37_dedale_window_inspection_amendment.yaml"


def _make_source(path: Path, *, mismatch_day: int | None = None) -> None:
    start = datetime(2024, 12, 23, tzinfo=timezone.utc)
    counter = 1
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("README.txt", "synthetic sentinel fixture\n")
        for day_index in range(1, 29):
            day = start + timedelta(days=day_index - 1)
            for hour in range(24):
                name = (
                    f"daily_winlogbeat/D{day_index}_H{hour}_"
                    f"{day.date().isoformat()}T{hour:02d}_winlogbeat_F{counter}.jsonl.bz2"
                )
                counter += 1
                if hour == 18:
                    event_day = day
                    if mismatch_day == day_index:
                        event_day = day + timedelta(days=1)
                    row = {
                        "@timestamp": event_day.replace(
                            hour=18, minute=0, second=0
                        ).isoformat(),
                        "agent": {"type": "winlogbeat"},
                        "host": {"name": "host-a"},
                        "event": {"code": "4688"},
                        "winlog": {
                            "channel": "Security",
                            "record_id": str(day_index),
                            "event_id": "4688",
                        },
                    }
                    payload = (json.dumps(row) + "\n").encode("utf-8")
                else:
                    payload = b""
                archive.writestr(name, bz2.compress(payload))


def _run(source: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source",
            str(source),
            "--adapter",
            str(ADAPTER),
            "--workers",
            "2",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_p2_37_window_sentinel_amendment_preserves_blinding() -> None:
    row = yaml.safe_load(AMENDMENT.read_text(encoding="utf-8"))
    assert row["status"] == "PRE_SCORING_METHOD_AMENDMENT"
    assert row["reason"]["labels_read_before_amendment"] is False
    assert row["reason"]["detector_run_before_amendment"] is False
    assert row["reason"]["detection_result_observed_before_amendment"] is False
    assert row["reason"]["source_changed"] is False
    assert row["reason"]["label_mapping_changed"] is False
    assert row["reason"]["scoring_window_policy_changed"] is False
    assert row["payload_sentinel_contract"]["selection"] == (
        "SMALLEST_NONEMPTY_MEMBER_PER_UTC_DATE"
    )
    assert row["payload_sentinel_contract"]["sentinel_count"] == 28
    assert row["window_derivation"]["expected_start"] == (
        "2025-01-06T00:00:00+00:00"
    )
    assert row["window_derivation"]["expected_end_exclusive"] == (
        "2025-01-20T00:00:00+00:00"
    )
    assert (
        row["superseded_execution"][
            "prior_partial_full_row_scans_are_canonical_evidence"
        ]
        is False
    )


def test_p2_37_window_sentinels_match_frozen_window_contract(
    tmp_path: Path,
) -> None:
    source = tmp_path / "dedale.zip"
    _make_source(source)

    proc = _run(source)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)

    assert result["status"] == "PASS"
    assert result["detection_rules_executed"] is False
    assert result["labels_read"] is False
    assert result["outer_file_count"] == 673
    assert result["source_data_files"] == 672
    assert result["distinct_utc_dates"] == 28
    assert result["members_per_date"] == 24
    assert result["sentinel_count"] == 28
    assert result["sentinel_rows"] == 28
    assert result["first_utc_date"] == "2024-12-23"
    assert result["last_utc_date"] == "2025-01-19"
    assert result["test_window_start"] == "2025-01-06T00:00:00+00:00"
    assert result["test_window_end_exclusive"] == "2025-01-20T00:00:00+00:00"
    assert all(
        item["member"].split("_H", 1)[1].startswith("18_")
        for item in result["sentinels"]
    )


def test_p2_37_window_sentinels_fail_closed_on_payload_date_mismatch(
    tmp_path: Path,
) -> None:
    source = tmp_path / "dedale-mismatch.zip"
    _make_source(source, mismatch_day=17)

    proc = _run(source)
    assert proc.returncode != 0
    assert "does not match filename date" in proc.stderr
