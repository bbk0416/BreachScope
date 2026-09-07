from __future__ import annotations

import asyncio

import pytest

from api.services.upload_policy import UploadBudget, stream_upload_to_path


class FakeUpload:
    def __init__(self, filename: str, payload: bytes):
        self.filename = filename
        self.payload = payload
        self.offset = 0

    async def read(self, size: int = -1):
        if size < 0:
            raise AssertionError("whole-file read() is forbidden")
        if self.offset >= len(self.payload):
            return b""
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


def test_stream_upload_refuses_existing_destination_without_deleting_it(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("BS_UPLOAD_CHUNK_BYTES", "4")
    monkeypatch.setenv("BS_UPLOAD_MAX_FILE_BYTES", "100")
    monkeypatch.setenv("BS_UPLOAD_MAX_TOTAL_BYTES", "100")

    destination = tmp_path / "Security.evtx"
    destination.write_bytes(b"original evidence")
    budget = UploadBudget()

    with pytest.raises(FileExistsError):
        asyncio.run(
            stream_upload_to_path(
                FakeUpload("Security.evtx", b"replacement"),
                destination,
                budget,
            )
        )

    assert destination.read_bytes() == b"original evidence"
    assert budget.total_bytes == 0


def test_bytes_upload_refuses_existing_destination_without_deleting_it(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("BS_UPLOAD_MAX_FILE_BYTES", "100")
    monkeypatch.setenv("BS_UPLOAD_MAX_TOTAL_BYTES", "100")

    destination = tmp_path / "Security.evtx"
    destination.write_bytes(b"original evidence")
    budget = UploadBudget()

    with pytest.raises(FileExistsError):
        asyncio.run(
            stream_upload_to_path(
                b"replacement",
                destination,
                budget,
                filename="Security.evtx",
            )
        )

    assert destination.read_bytes() == b"original evidence"
    assert budget.total_bytes == 0


def test_p2_08d_marker_present():
    import api.services.upload_policy as upload_policy

    source = open(upload_policy.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P2_08D_EXCLUSIVE_UPLOAD_CREATE_V1" in source
