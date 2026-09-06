from __future__ import annotations

from datetime import datetime
import os

from breachscope.artifacts import prefetch


def test_prefetch_metadata_does_not_claim_filesystem_mtime_as_execution_time(tmp_path):
    pf_path = tmp_path / "NOTEPAD.EXE-A1B2C3D4.pf"
    pf_path.write_bytes(b"not-a-real-prefetch-body")
    observed_epoch = 1_700_000_000
    os.utime(pf_path, (observed_epoch, observed_epoch))

    event = prefetch._parse_prefetch_file(pf_path)

    assert event is not None
    expected_mtime = datetime.fromtimestamp(observed_epoch).isoformat()
    assert event["timestamp"] == expected_mtime
    assert event["source"] == "Prefetch"
    assert event["event_id"] == "prefetch_file_observed"
    assert event["event_type"] == "artifact_observation"
    assert event["command_line"] == ""

    raw = event["raw"]
    assert raw["program_name"] == "NOTEPAD.EXE"
    assert raw["filename_hash"] == "A1B2C3D4"
    assert raw["filesystem_mtime"] == expected_mtime
    assert raw["timestamp_source"] == "filesystem_mtime"
    assert raw["parser_mode"] == "metadata_only"
    assert raw["execution_time_verified"] is False
    assert raw["execution_times"] == []
    assert "last_execution" not in raw


def test_collect_prefetch_emits_metadata_observation_only(tmp_path, monkeypatch):
    monkeypatch.setattr(prefetch.platform, "system", lambda: "Windows")
    (tmp_path / "CMD.EXE-DEADBEEF.pf").write_bytes(b"metadata-only")
    (tmp_path / "ignore.txt").write_text("ignore", encoding="utf-8")

    events = prefetch.collect_prefetch(prefetch_dir=tmp_path)

    assert len(events) == 1
    assert events[0]["event_id"] == "prefetch_file_observed"
    assert events[0]["raw"]["execution_time_verified"] is False
    assert "last_execution" not in events[0]["raw"]


def test_collect_prefetch_non_windows_behavior_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(prefetch.platform, "system", lambda: "Linux")
    (tmp_path / "CMD.EXE-DEADBEEF.pf").write_bytes(b"metadata-only")

    assert prefetch.collect_prefetch(prefetch_dir=tmp_path) == []


def test_prefetch_filename_without_hash_remains_metadata_only(tmp_path):
    pf_path = tmp_path / "ODDNAME.pf"
    pf_path.write_bytes(b"metadata-only")

    event = prefetch._parse_prefetch_file(pf_path)

    assert event is not None
    assert event["raw"]["program_name"] == "ODDNAME"
    assert event["raw"]["filename_hash"] == ""
    assert event["raw"]["execution_times"] == []
