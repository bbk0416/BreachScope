from __future__ import annotations

import json
from pathlib import Path

import pytest

from breachscope.release import build_release_bundle
from breachscope.release_signing import (
    DEFAULT_SIGNATURE_NAME,
    RELEASE_SIGNING_PRIVATE_KEY_ENV,
    ReleaseSignatureError,
    generate_release_signing_keypair,
    sign_release_manifest,
    verify_release_manifest_signature,
)


def _minimal_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        """
[project]
name = "breachscope-signing-test"
version = "1.2.3"
description = "release signing test"
requires-python = ">=3.10"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text("# signing test\n", encoding="utf-8")
    (repo / "breachscope").mkdir()
    (repo / "breachscope" / "__init__.py").write_text("", encoding="utf-8")
    return repo


def test_release_manifest_sign_and_verify_with_trusted_public_key(
    tmp_path: Path,
) -> None:
    pair = generate_release_signing_keypair()
    manifest = tmp_path / "release_manifest.json"
    manifest.write_text('{"release":"ok"}\n', encoding="utf-8")
    signature = tmp_path / DEFAULT_SIGNATURE_NAME

    signed = sign_release_manifest(
        manifest,
        signature,
        private_key_b64=pair["private_key"],
    )
    assert signed["algorithm"] == "Ed25519"
    assert signed["public_key"] == pair["public_key"]
    assert signed["public_key_sha256"] == pair["public_key_sha256"]

    embedded_only = verify_release_manifest_signature(manifest, signature)
    assert embedded_only["valid"] is True
    assert embedded_only["trusted_public_key_supplied"] is False

    trusted = verify_release_manifest_signature(
        manifest,
        signature,
        expected_public_key_b64=pair["public_key"],
    )
    assert trusted["valid"] is True
    assert trusted["trusted_public_key_supplied"] is True
    assert trusted["public_key_sha256"] == pair["public_key_sha256"]


def test_release_signature_fails_after_manifest_tamper(tmp_path: Path) -> None:
    pair = generate_release_signing_keypair()
    manifest = tmp_path / "release_manifest.json"
    manifest.write_text('{"release":"ok"}\n', encoding="utf-8")
    signature = tmp_path / DEFAULT_SIGNATURE_NAME
    sign_release_manifest(
        manifest,
        signature,
        private_key_b64=pair["private_key"],
    )

    manifest.write_text('{"release":"tampered"}\n', encoding="utf-8")
    with pytest.raises(
        ReleaseSignatureError,
        match="SHA-256",
    ):
        verify_release_manifest_signature(manifest, signature)


def test_release_signature_rejects_wrong_trusted_public_key(
    tmp_path: Path,
) -> None:
    signer = generate_release_signing_keypair()
    other = generate_release_signing_keypair()
    manifest = tmp_path / "release_manifest.json"
    manifest.write_text('{"release":"ok"}\n', encoding="utf-8")
    signature = tmp_path / DEFAULT_SIGNATURE_NAME
    sign_release_manifest(
        manifest,
        signature,
        private_key_b64=signer["private_key"],
    )

    with pytest.raises(
        ReleaseSignatureError,
        match="trusted public key",
    ):
        verify_release_manifest_signature(
            manifest,
            signature,
            expected_public_key_b64=other["public_key"],
        )


def test_release_signing_rejects_invalid_private_key(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "release_manifest.json"
    manifest.write_text("{}\n", encoding="utf-8")
    with pytest.raises(
        ReleaseSignatureError,
        match="exactly 32 bytes",
    ):
        sign_release_manifest(
            manifest,
            tmp_path / DEFAULT_SIGNATURE_NAME,
            private_key_b64="YWJj",
        )


def test_release_bundle_signs_when_key_is_configured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _minimal_repo(tmp_path)
    dist = repo / "dist"
    pair = generate_release_signing_keypair()
    monkeypatch.setenv(
        RELEASE_SIGNING_PRIVATE_KEY_ENV,
        pair["private_key"],
    )

    result = build_release_bundle(repo, dist)
    names = {Path(item["path"]).name for item in result["artifacts"]}
    assert DEFAULT_SIGNATURE_NAME in names
    assert result["signing"]["enabled"] is True
    assert (
        result["signing"]["public_key_sha256"]
        == pair["public_key_sha256"]
    )

    verified = verify_release_manifest_signature(
        dist / "release_manifest.json",
        dist / DEFAULT_SIGNATURE_NAME,
        expected_public_key_b64=pair["public_key"],
    )
    assert verified["valid"] is True

    envelope = json.loads(
        (dist / DEFAULT_SIGNATURE_NAME).read_text(encoding="utf-8")
    )
    serialized = json.dumps(envelope, ensure_ascii=False)
    assert pair["private_key"] not in serialized


def test_unsigned_rebuild_removes_stale_signature(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _minimal_repo(tmp_path)
    dist = repo / "dist"
    pair = generate_release_signing_keypair()
    monkeypatch.setenv(
        RELEASE_SIGNING_PRIVATE_KEY_ENV,
        pair["private_key"],
    )
    build_release_bundle(repo, dist)
    signature = dist / DEFAULT_SIGNATURE_NAME
    assert signature.exists()

    monkeypatch.delenv(RELEASE_SIGNING_PRIVATE_KEY_ENV, raising=False)
    result = build_release_bundle(repo, dist)

    assert result["signing"]["enabled"] is False
    assert not signature.exists()
    assert DEFAULT_SIGNATURE_NAME not in {
        Path(item["path"]).name for item in result["artifacts"]
    }
