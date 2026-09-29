"""Streaming re-analysis inputs from a verified retained case."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from api.services.artifact_encryption import (
    iter_artifact_chunks,
    plaintext_path,
)
from api.services.path_boundary import validate_managed_work_dir


class CaseReanalysisError(RuntimeError):
    """Raised when a retained case cannot provide safe re-analysis inputs."""


class RetainedArtifactUpload:
    """Upload-like source that streams retained plaintext on demand."""

    def __init__(
        self,
        logical_path: Path,
        root: Path,
        *,
        filename: str,
    ):
        self.filename = str(filename)
        self._logical_path = Path(logical_path)
        self._root = Path(root)
        self._iterator: Iterator[bytes] | None = None
        self._buffer = bytearray()
        self._eof = False
        self._closed = False

    def _ensure_iterator(self) -> Iterator[bytes]:
        if self._iterator is None:
            self._iterator = iter(
                iter_artifact_chunks(
                    self._logical_path,
                    self._root,
                )
            )
        return self._iterator

    def read(self, size: int = -1) -> bytes:
        if self._closed or (self._eof and not self._buffer):
            return b""
        iterator = self._ensure_iterator()
        if size is None or size < 0:
            for chunk in iterator:
                self._buffer.extend(chunk)
            self._eof = True
            data = bytes(self._buffer)
            self._buffer.clear()
            return data
        if size == 0:
            return b""
        while len(self._buffer) < size and not self._eof:
            try:
                self._buffer.extend(next(iterator))
            except StopIteration:
                self._eof = True
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def close(self) -> None:
        self._closed = True
        iterator = self._iterator
        self._iterator = None
        self._buffer.clear()
        if iterator is not None:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()


def retained_case_uploads(
    work_dir: str | Path,
) -> list[RetainedArtifactUpload]:
    """Return streaming sources for retained browser-upload inputs.

    Both plaintext and authenticated encrypted retained inputs are supported.
    Cases produced only from ephemeral collection inputs are rejected because
    the original evidence is not present in the retained case.
    """
    root = validate_managed_work_dir(
        work_dir,
        allow_temp=True,
        must_exist=True,
    )
    input_root = root / "input"
    if not input_root.is_dir():
        raise CaseReanalysisError(
            "Retained case does not contain an input directory."
        )

    logical_rows: dict[str, tuple[Path, Path]] = {}
    for stored in sorted(
        path for path in input_root.rglob("*") if path.is_file()
    ):
        logical = (
            plaintext_path(stored)
            if stored.name.endswith(".enc")
            else stored
        )
        try:
            relative = logical.relative_to(input_root)
        except ValueError as exc:
            raise CaseReanalysisError(
                "Retained input artifact is outside the input directory."
            ) from exc
        if not relative.parts or any(
            part in {"", ".", ".."} for part in relative.parts
        ):
            raise CaseReanalysisError(
                "Retained input artifact has an unsafe relative path."
            )
        key = relative.as_posix().casefold()
        if key in logical_rows:
            raise CaseReanalysisError(
                "Retained input contains ambiguous plaintext/encrypted duplicates."
            )
        logical_rows[key] = (logical, relative)

    if not logical_rows:
        raise CaseReanalysisError(
            "Retained case does not contain re-analyzable input artifacts."
        )

    sources: list[RetainedArtifactUpload] = []
    emitted_names: set[str] = set()
    for logical, relative in logical_rows.values():
        filename = "__".join(relative.parts)
        normalized_name = filename.casefold()
        if normalized_name in emitted_names:
            raise CaseReanalysisError(
                "Retained input paths collide after safe upload-name normalization."
            )
        emitted_names.add(normalized_name)
        sources.append(
            RetainedArtifactUpload(
                logical,
                root,
                filename=filename,
            )
        )
    return sources


def close_reanalysis_uploads(
    sources: list[RetainedArtifactUpload],
) -> None:
    for source in sources:
        source.close()


DecryptedArtifactUpload = RetainedArtifactUpload

__all__ = [
    "CaseReanalysisError",
    "DecryptedArtifactUpload",
    "RetainedArtifactUpload",
    "close_reanalysis_uploads",
    "retained_case_uploads",
]
