"""Streaming upload limits for BreachScope web analysis.

P1-01 invariants:
- never materialize a complete UploadFile in memory;
- enforce file-count, per-file, aggregate-upload and request-size ceilings;
- unlink the partial destination when a streamed write is rejected or fails;
- limit values are configurable through environment variables.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


DEFAULT_CHUNK_BYTES = 1_048_576
DEFAULT_MAX_FILE_BYTES = 536_870_912
DEFAULT_MAX_TOTAL_BYTES = 1_073_741_824
DEFAULT_MAX_FILES = 32
DEFAULT_MAX_REQUEST_BYTES = 1_107_296_256


class UploadLimitError(ValueError):
    """An upload exceeded a configured BreachScope safety limit."""


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise UploadLimitError(f"{name} must be an integer") from exc
    if value <= 0:
        raise UploadLimitError(f"{name} must be greater than zero")
    return value


def chunk_bytes() -> int:
    return _positive_int_env("BS_UPLOAD_CHUNK_BYTES", DEFAULT_CHUNK_BYTES)


def max_file_bytes() -> int:
    return _positive_int_env("BS_UPLOAD_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES)


def max_total_bytes() -> int:
    return _positive_int_env("BS_UPLOAD_MAX_TOTAL_BYTES", DEFAULT_MAX_TOTAL_BYTES)


def max_files() -> int:
    return _positive_int_env("BS_UPLOAD_MAX_FILES", DEFAULT_MAX_FILES)


def max_request_bytes() -> int:
    return _positive_int_env("BS_UPLOAD_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES)


def validate_file_count(files: list[Any] | None) -> None:
    count = len(files or [])
    limit = max_files()
    if count > limit:
        raise UploadLimitError(
            f"Too many uploaded files: {count}; maximum is {limit}"
        )


@dataclass
class UploadBudget:
    total_bytes: int = 0

    def add(self, amount: int, *, filename: str) -> None:
        proposed = self.total_bytes + amount
        limit = max_total_bytes()
        if proposed > limit:
            raise UploadLimitError(
                f"Total upload limit exceeded while reading {filename!r}: "
                f"{proposed} bytes > {limit} bytes"
            )
        self.total_bytes = proposed


async def _read_chunk(source: Any, size: int) -> bytes:
    read = getattr(source, "read", None)
    if read is None:
        if isinstance(source, (bytes, bytearray, memoryview)):
            return bytes(source)
        raise TypeError("Upload source does not provide read()")

    result = read(size)
    if hasattr(result, "__await__"):
        result = await result

    if result is None:
        return b""
    if isinstance(result, memoryview):
        result = result.tobytes()
    if isinstance(result, bytearray):
        result = bytes(result)
    if not isinstance(result, bytes):
        raise TypeError("Upload read() must return bytes")
    return result


async def stream_upload_to_path(
    source: Any,
    destination: Path,
    budget: UploadBudget,
    *,
    filename: str | None = None,
) -> int:
    destination = Path(destination)
    label = filename or getattr(source, "filename", None) or destination.name
    per_file_limit = max_file_bytes()
    block_size = chunk_bytes()
    written = 0

    if isinstance(source, (bytes, bytearray, memoryview)):
        blob = bytes(source)
        if len(blob) > per_file_limit:
            raise UploadLimitError(
                f"File {label!r} exceeds per-file limit: "
                f"{len(blob)} bytes > {per_file_limit} bytes"
            )
        budget.add(len(blob), filename=label)
        try:
            with destination.open("wb") as handle:
                handle.write(blob)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return len(blob)

    try:
        with destination.open("wb") as handle:
            while True:
                chunk = await _read_chunk(source, block_size)
                if not chunk:
                    break

                proposed_file = written + len(chunk)
                if proposed_file > per_file_limit:
                    raise UploadLimitError(
                        f"File {label!r} exceeds per-file limit: "
                        f"{proposed_file} bytes > {per_file_limit} bytes"
                    )

                budget.add(len(chunk), filename=label)
                handle.write(chunk)
                written = proposed_file
    except Exception:
        destination.unlink(missing_ok=True)
        raise

    return written


class UploadRequestLimitMiddleware(BaseHTTPMiddleware):
    """Reject obviously oversized /api/analyze requests before body parsing."""

    async def dispatch(self, request, call_next):
        if request.url.path == "/api/analyze":
            raw = request.headers.get("content-length", "").strip()
            if raw:
                try:
                    length = int(raw)
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "detail": "Invalid Content-Length header.",
                            "code": "INVALID_CONTENT_LENGTH",
                        },
                    )

                limit = max_request_bytes()
                if length > limit:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": (
                                f"Request body is too large: "
                                f"{length} bytes > {limit} bytes"
                            ),
                            "code": "UPLOAD_LIMIT_EXCEEDED",
                        },
                    )

        return await call_next(request)
