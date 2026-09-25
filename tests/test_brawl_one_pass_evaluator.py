import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from scripts.brawl_attack_holdout_one_pass import (
    BrawlOnePassError,
    _data_members,
    _git_blob_sha1,
    _iter_json_records,
)


def test_git_blob_sha1_matches_git_object_framing(tmp_path: Path):
    path = tmp_path / "archive.bin"
    payload = b"abc123\n"
    path.write_bytes(payload)

    expected = hashlib.sha1(
        f"blob {len(payload)}\0".encode("ascii") + payload
    ).hexdigest()

    assert _git_blob_sha1(path) == expected


def test_iter_json_records_accepts_array_and_jsonl():
    array_records = list(
        _iter_json_records(
            json.dumps([{"type": "sysmon"}, {"type": "win_event"}]).encode(),
            "data/a.json",
        )
    )
    jsonl_records = list(
        _iter_json_records(
            b'{"type":"sysmon"}\n{"type":"bsf_events"}\n',
            "data/b.jsonl",
        )
    )

    assert [item["type"] for item in array_records] == ["sysmon", "win_event"]
    assert [item["type"] for item in jsonl_records] == ["sysmon", "bsf_events"]


def test_data_members_accepts_prefixed_data_directory(tmp_path: Path):
    path = tmp_path / "fixture.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("brawl-public-game-001/data/sysmon.json", "{}")
        archive.writestr("README.md", "not data")

    with zipfile.ZipFile(path) as archive:
        members = _data_members(archive)

    assert [item.filename for item in members] == [
        "brawl-public-game-001/data/sysmon.json"
    ]


def test_data_members_rejects_archive_without_documented_data_directory(tmp_path: Path):
    path = tmp_path / "fixture.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("README.md", "{}")

    with zipfile.ZipFile(path) as archive:
        with pytest.raises(BrawlOnePassError, match="no files under data/"):
            _data_members(archive)


def test_invalid_member_framing_fails_closed():
    with pytest.raises(BrawlOnePassError, match="unsupported JSON framing"):
        list(_iter_json_records(b'{"type":"sysmon"}\nnot-json\n', "data/a"))
