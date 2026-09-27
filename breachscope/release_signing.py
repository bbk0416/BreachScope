"""Ed25519 signing helpers for BreachScope release manifests."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


RELEASE_SIGNING_PRIVATE_KEY_ENV = "BS_RELEASE_SIGNING_PRIVATE_KEY"
SIGNATURE_SCHEMA = "breachscope.release-signature.v1"
SIGNATURE_ALGORITHM = "Ed25519"
DEFAULT_SIGNATURE_NAME = "release_manifest.sig.json"


class ReleaseSignatureError(RuntimeError):
    pass


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str, *, label: str) -> bytes:
    raw = str(value or "").strip()
    if not raw:
        raise ReleaseSignatureError(f"{label} is empty.")
    try:
        padding = "=" * (-len(raw) % 4)
        return base64.b64decode(
            (raw + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise ReleaseSignatureError(
            f"{label} must be URL-safe base64."
        ) from exc


def release_signing_key_configured() -> bool:
    return bool(os.getenv(RELEASE_SIGNING_PRIVATE_KEY_ENV, "").strip())


def _private_key_from_b64(value: str) -> Ed25519PrivateKey:
    raw = _b64decode(value, label=RELEASE_SIGNING_PRIVATE_KEY_ENV)
    if len(raw) != 32:
        raise ReleaseSignatureError(
            f"{RELEASE_SIGNING_PRIVATE_KEY_ENV} must decode to exactly 32 bytes."
        )
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise ReleaseSignatureError("Invalid Ed25519 private key.") from exc


def _public_key_from_b64(value: str) -> Ed25519PublicKey:
    raw = _b64decode(value, label="release public key")
    if len(raw) != 32:
        raise ReleaseSignatureError(
            "Release public key must decode to exactly 32 bytes."
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise ReleaseSignatureError("Invalid Ed25519 public key.") from exc


def _public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_fingerprint(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()


def generate_release_signing_keypair() -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = _public_key_bytes(private_key.public_key())
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "private_key": _b64encode(private_bytes),
        "public_key": _b64encode(public_bytes),
        "public_key_sha256": public_key_fingerprint(public_bytes),
    }


def sign_release_manifest(
    manifest_path: str | Path,
    signature_path: str | Path | None = None,
    *,
    private_key_b64: str | None = None,
) -> dict[str, Any]:
    manifest = Path(manifest_path).resolve()
    if not manifest.is_file():
        raise ReleaseSignatureError(
            f"Release manifest does not exist: {manifest}"
        )

    private_value = (
        private_key_b64
        if private_key_b64 is not None
        else os.getenv(RELEASE_SIGNING_PRIVATE_KEY_ENV, "")
    )
    private_key = _private_key_from_b64(private_value)
    public_bytes = _public_key_bytes(private_key.public_key())
    manifest_bytes = manifest.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    signature = private_key.sign(manifest_bytes)

    envelope = {
        "schema": SIGNATURE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "signed_file": manifest.name,
        "signed_file_sha256": manifest_sha256,
        "public_key": _b64encode(public_bytes),
        "public_key_sha256": public_key_fingerprint(public_bytes),
        "signature": _b64encode(signature),
    }

    output = (
        Path(signature_path).resolve()
        if signature_path is not None
        else manifest.with_name(DEFAULT_SIGNATURE_NAME)
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return {
        "signature_path": str(output),
        **envelope,
    }


def verify_release_manifest_signature(
    manifest_path: str | Path,
    signature_path: str | Path,
    *,
    expected_public_key_b64: str | None = None,
) -> dict[str, Any]:
    manifest = Path(manifest_path).resolve()
    signature_file = Path(signature_path).resolve()
    if not manifest.is_file():
        raise ReleaseSignatureError(
            f"Release manifest does not exist: {manifest}"
        )
    if not signature_file.is_file():
        raise ReleaseSignatureError(
            f"Release signature does not exist: {signature_file}"
        )

    try:
        envelope = json.loads(signature_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ReleaseSignatureError(
            f"Invalid release signature JSON: {signature_file}"
        ) from exc
    if not isinstance(envelope, dict):
        raise ReleaseSignatureError("Release signature payload must be an object.")

    if envelope.get("schema") != SIGNATURE_SCHEMA:
        raise ReleaseSignatureError("Unsupported release signature schema.")
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise ReleaseSignatureError("Unsupported release signature algorithm.")
    if envelope.get("signed_file") != manifest.name:
        raise ReleaseSignatureError(
            "Release signature targets a different manifest filename."
        )

    manifest_bytes = manifest.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if envelope.get("signed_file_sha256") != manifest_sha256:
        raise ReleaseSignatureError(
            "Release manifest SHA-256 does not match the signature envelope."
        )

    embedded_public_key = str(envelope.get("public_key") or "")
    embedded_public = _public_key_from_b64(embedded_public_key)
    embedded_public_bytes = _public_key_bytes(embedded_public)
    fingerprint = public_key_fingerprint(embedded_public_bytes)
    if envelope.get("public_key_sha256") != fingerprint:
        raise ReleaseSignatureError(
            "Release public-key fingerprint does not match the signature envelope."
        )

    trusted_key_supplied = expected_public_key_b64 is not None
    if expected_public_key_b64 is not None:
        expected_public = _public_key_from_b64(expected_public_key_b64)
        expected_bytes = _public_key_bytes(expected_public)
        if expected_bytes != embedded_public_bytes:
            raise ReleaseSignatureError(
                "Release signature public key does not match the trusted public key."
            )

    signature = _b64decode(
        str(envelope.get("signature") or ""),
        label="release signature",
    )
    if len(signature) != 64:
        raise ReleaseSignatureError(
            "Ed25519 release signature must decode to exactly 64 bytes."
        )
    try:
        embedded_public.verify(signature, manifest_bytes)
    except InvalidSignature as exc:
        raise ReleaseSignatureError(
            "Release manifest signature verification failed."
        ) from exc

    return {
        "valid": True,
        "schema": SIGNATURE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "manifest_path": str(manifest),
        "signature_path": str(signature_file),
        "manifest_sha256": manifest_sha256,
        "public_key": embedded_public_key,
        "public_key_sha256": fingerprint,
        "trusted_public_key_supplied": trusted_key_supplied,
    }


__all__ = [
    "DEFAULT_SIGNATURE_NAME",
    "RELEASE_SIGNING_PRIVATE_KEY_ENV",
    "ReleaseSignatureError",
    "generate_release_signing_keypair",
    "public_key_fingerprint",
    "release_signing_key_configured",
    "sign_release_manifest",
    "verify_release_manifest_signature",
]
