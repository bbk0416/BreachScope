import os

from breachscope.artifacts import prefetch


def test_prefetch_filesystem_mtime_is_explicit_utc(tmp_path):
    pf_path = tmp_path / "POWERSHELL.EXE-ABCDEF01.pf"
    pf_path.write_bytes(b"prefetch-fixture")
    os.utime(pf_path, (1_700_000_000, 1_700_000_000))

    event = prefetch._parse_prefetch_file(pf_path)

    assert event is not None
    assert event["timestamp"] == "2023-11-14T22:13:20+00:00"
    assert event["raw"]["filesystem_mtime"] == event["timestamp"]
    assert event["raw"]["timestamp_source"] == "filesystem_mtime"
    assert event["raw"]["parser_mode"] == "metadata_only"
    assert event["raw"]["execution_time_verified"] is False
    assert event["raw"]["execution_times"] == []
