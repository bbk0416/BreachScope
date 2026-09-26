"""Opt-in authenticated encryption for retained case artifacts.

The on-disk format is chunked so uploads near the product's 512 MiB per-file
limit are never materialized in memory during encryption/decryption.

Format (v2):
    MAGIC | nonce_base(12) | plaintext_size(8)
    repeated: plaintext_chunk_size(4) | AESGCM(ciphertext + 16-byte tag)
    final: 0(4) | AESGCM(empty plaintext + 16-byte tag)

Each chunk is independently authenticated and binds the logical relative path,
total plaintext size, chunk index and chunk size as AAD. The final empty record
authenticates file completeness so truncation fails closed.
"""
from __future__ import annotations

import base64
import os
import struct
import tempfile
from pathlib import Path
from typing import Iterable, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ARTIFACT_ENCRYPTION_KEY_ENV = "BS_ARTIFACT_ENCRYPTION_KEY"
MAGIC = b"BSENC2\x00"
NONCE_BASE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1_048_576
ENCRYPTED_SUFFIX = ".enc"


class ArtifactEncryptionError(RuntimeError):
    pass


def artifact_encryption_enabled() -> bool:
    return bool(os.getenv(ARTIFACT_ENCRYPTION_KEY_ENV, "").strip())


def _decode_key(raw: str | None = None) -> bytes:
    value = str(
        os.getenv(ARTIFACT_ENCRYPTION_KEY_ENV, "") if raw is None else raw
    ).strip()
    if not value:
        raise ArtifactEncryptionError(
            f"{ARTIFACT_ENCRYPTION_KEY_ENV} is not configured."
        )
    try:
        padding = "=" * (-len(value) % 4)
        key = base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise ArtifactEncryptionError(
            f"{ARTIFACT_ENCRYPTION_KEY_ENV} must be URL-safe base64."
        ) from exc
    if len(key) != 32:
        raise ArtifactEncryptionError(
            f"{ARTIFACT_ENCRYPTION_KEY_ENV} must decode to exactly 32 bytes."
        )
    return key


def validate_artifact_encryption_key_value(value: str) -> None:
    _decode_key(value)


def validate_artifact_encryption_key() -> None:
    if artifact_encryption_enabled():
        _decode_key()


def encrypted_path(path: Path) -> Path:
    return path.with_name(path.name + ENCRYPTED_SUFFIX)


def plaintext_path(path: Path) -> Path:
    if path.name.endswith(ENCRYPTED_SUFFIX):
        return path.with_name(path.name[: -len(ENCRYPTED_SUFFIX)])
    return path


def artifact_exists(path: Path) -> bool:
    return path.is_file() or encrypted_path(path).is_file()


def _relative_path_bytes(path: Path, root: Path) -> bytes:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ArtifactEncryptionError(
            f"artifact path is outside encryption root: {path}"
        ) from exc
    return rel.as_posix().encode("utf-8")


def _nonce(base: bytes, index: int) -> bytes:
    if len(base) != NONCE_BASE_SIZE:
        raise ArtifactEncryptionError("invalid encrypted artifact nonce base")
    if index < 0:
        raise ArtifactEncryptionError("invalid encrypted artifact chunk index")
    value = int.from_bytes(base, "big") + index
    if value >= 2 ** (NONCE_BASE_SIZE * 8):
        raise ArtifactEncryptionError("encrypted artifact nonce space exhausted")
    return value.to_bytes(NONCE_BASE_SIZE, "big")


def _aad(
    original: Path,
    root: Path,
    total_size: int,
    index: int,
    chunk_size: int,
) -> bytes:
    return b"\x00".join(
        [
            _relative_path_bytes(original, root),
            total_size.to_bytes(8, "big"),
            index.to_bytes(4, "big"),
            chunk_size.to_bytes(4, "big"),
        ]
    )


def _read_exact(handle, size: int, *, label: str) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise ArtifactEncryptionError(
            f"truncated encrypted artifact while reading {label}"
        )
    return data


def encrypt_file(
    path: Path,
    root: Path,
    *,
    key: bytes | None = None,
    delete_source: bool = True,
) -> Path:
    path = path.resolve()
    root = root.resolve()
    if not path.is_file():
        raise ArtifactEncryptionError(f"artifact file does not exist: {path}")
    if path.name.endswith(ENCRYPTED_SUFFIX):
        raise ArtifactEncryptionError(f"artifact is already encrypted: {path}")

    _relative_path_bytes(path, root)

    destination = encrypted_path(path)
    if destination.exists():
        raise ArtifactEncryptionError(
            f"encrypted artifact already exists: {destination}"
        )

    key_bytes = key or _decode_key()
    cipher = AESGCM(key_bytes)
    nonce_base = os.urandom(NONCE_BASE_SIZE)
    total_size = path.stat().st_size

    fd, tmp_name = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    tmp = Path(tmp_name)
    try:
        with path.open("rb") as source, os.fdopen(fd, "wb") as target:
            target.write(MAGIC)
            target.write(nonce_base)
            target.write(struct.pack(">Q", total_size))

            index = 0
            read_total = 0
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                size = len(chunk)
                aad = _aad(path, root, total_size, index, size)
                encrypted = cipher.encrypt(
                    _nonce(nonce_base, index),
                    chunk,
                    aad,
                )
                target.write(struct.pack(">I", size))
                target.write(encrypted)
                read_total += size
                index += 1

            if read_total != total_size:
                raise ArtifactEncryptionError(
                    "artifact changed while it was being encrypted"
                )

            aad = _aad(path, root, total_size, index, 0)
            target.write(struct.pack(">I", 0))
            target.write(
                cipher.encrypt(_nonce(nonce_base, index), b"", aad)
            )
            target.flush()
            os.fsync(target.fileno())

        tmp.replace(destination)
        if delete_source:
            path.unlink()
    except Exception:
        if destination.exists() and path.exists():
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    return destination


def _iter_encrypted_plaintext(
    path: Path,
    root: Path,
    *,
    key: bytes | None = None,
) -> Iterator[bytes]:
    root = root.resolve()
    encrypted = (
        path.resolve()
        if path.name.endswith(ENCRYPTED_SUFFIX)
        else encrypted_path(path.resolve())
    )
    if not encrypted.is_file():
        raise ArtifactEncryptionError(
            f"encrypted artifact does not exist: {encrypted}"
        )

    original = plaintext_path(encrypted)
    key_bytes = key or _decode_key()
    cipher = AESGCM(key_bytes)

    with encrypted.open("rb") as handle:
        magic = _read_exact(handle, len(MAGIC), label="magic")
        if magic != MAGIC:
            raise ArtifactEncryptionError(
                f"invalid encrypted artifact format: {encrypted}"
            )
        nonce_base = _read_exact(
            handle, NONCE_BASE_SIZE, label="nonce base"
        )
        total_size = struct.unpack(
            ">Q", _read_exact(handle, 8, label="plaintext size")
        )[0]

        remaining = total_size
        index = 0
        while remaining:
            size = struct.unpack(
                ">I", _read_exact(handle, 4, label="chunk size")
            )[0]
            if size <= 0 or size > CHUNK_SIZE or size > remaining:
                raise ArtifactEncryptionError(
                    f"invalid encrypted artifact chunk size: {size}"
                )
            encrypted_chunk = _read_exact(
                handle,
                size + TAG_SIZE,
                label="encrypted chunk",
            )
            aad = _aad(original, root, total_size, index, size)
            try:
                plaintext = cipher.decrypt(
                    _nonce(nonce_base, index),
                    encrypted_chunk,
                    aad,
                )
            except Exception as exc:
                raise ArtifactEncryptionError(
                    f"artifact authentication/decryption failed: {encrypted}"
                ) from exc
            if len(plaintext) != size:
                raise ArtifactEncryptionError(
                    "decrypted artifact chunk length mismatch"
                )
            remaining -= size
            index += 1
            yield plaintext

        final_size = struct.unpack(
            ">I", _read_exact(handle, 4, label="terminator size")
        )[0]
        if final_size != 0:
            raise ArtifactEncryptionError(
                "encrypted artifact terminator is missing"
            )
        final_ciphertext = _read_exact(
            handle, TAG_SIZE, label="terminator tag"
        )
        aad = _aad(original, root, total_size, index, 0)
        try:
            final_plaintext = cipher.decrypt(
                _nonce(nonce_base, index),
                final_ciphertext,
                aad,
            )
        except Exception as exc:
            raise ArtifactEncryptionError(
                f"artifact authentication/decryption failed: {encrypted}"
            ) from exc
        if final_plaintext:
            raise ArtifactEncryptionError(
                "encrypted artifact terminator is invalid"
            )
        if handle.read(1):
            raise ArtifactEncryptionError(
                "encrypted artifact has trailing bytes"
            )


def iter_artifact_chunks(
    path: Path,
    root: Path,
    *,
    chunk_size: int = CHUNK_SIZE,
) -> Iterator[bytes]:
    path = path.resolve()
    if path.is_file() and not path.name.endswith(ENCRYPTED_SUFFIX):
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        return
    yield from _iter_encrypted_plaintext(path, root)


def verify_artifact(path: Path, root: Path) -> None:
    if path.is_file() and not path.name.endswith(ENCRYPTED_SUFFIX):
        return
    for _ in _iter_encrypted_plaintext(path, root):
        pass


def decrypt_bytes(path: Path, root: Path, *, key: bytes | None = None) -> bytes:
    if key is not None:
        return b"".join(
            _iter_encrypted_plaintext(path, root, key=key)
        )
    return read_artifact_bytes(path, root)


def read_artifact_bytes(path: Path, root: Path) -> bytes:
    if path.is_file() and not path.name.endswith(ENCRYPTED_SUFFIX):
        return path.read_bytes()
    return b"".join(_iter_encrypted_plaintext(path, root))


def _restore_plaintext(
    encrypted: Path,
    original: Path,
    root: Path,
    *,
    key: bytes,
) -> None:
    original.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=original.name + ".",
        suffix=".restore.tmp",
        dir=str(original.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            for chunk in _iter_encrypted_plaintext(
                encrypted, root, key=key
            ):
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(original)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def encrypt_tree(
    root: Path,
    *,
    exclude: Iterable[Path] | None = None,
) -> list[Path]:
    """Encrypt a retained work tree with rollback on normal failures.

    Ciphertexts are fully generated and authenticated first while plaintext
    sources remain untouched. Only after every file encrypts successfully are
    plaintexts removed. If removal fails, already-removed sources are restored
    from their ciphertext and generated ciphertexts are removed.
    """
    root = root.resolve()
    if not root.is_dir():
        raise ArtifactEncryptionError(
            f"artifact root does not exist: {root}"
        )
    key = _decode_key()
    excluded = {p.resolve() for p in (exclude or [])}
    files = sorted(
        p.resolve()
        for p in root.rglob("*")
        if p.is_file() and not p.name.endswith(ENCRYPTED_SUFFIX)
    )
    files = [path for path in files if path not in excluded]

    encrypted: list[Path] = []
    try:
        for path in files:
            encrypted.append(
                encrypt_file(
                    path,
                    root,
                    key=key,
                    delete_source=False,
                )
            )
    except Exception:
        for destination in encrypted:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    removed: list[tuple[Path, Path]] = []
    try:
        for source, destination in zip(files, encrypted):
            source.unlink()
            removed.append((source, destination))
    except Exception as exc:
        rollback_errors: list[str] = []
        for source, destination in reversed(removed):
            try:
                _restore_plaintext(
                    destination,
                    source,
                    root,
                    key=key,
                )
            except Exception as restore_exc:
                rollback_errors.append(
                    f"{source}: {restore_exc}"
                )
        if not rollback_errors:
            for destination in encrypted:
                try:
                    destination.unlink(missing_ok=True)
                except OSError as cleanup_exc:
                    rollback_errors.append(
                        f"{destination}: {cleanup_exc}"
                    )
        if rollback_errors:
            raise ArtifactEncryptionError(
                "artifact encryption commit failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise ArtifactEncryptionError(
            "artifact encryption commit failed; plaintext state was restored"
        ) from exc

    return encrypted
