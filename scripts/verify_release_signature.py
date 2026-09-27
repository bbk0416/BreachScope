#!/usr/bin/env python3
"""Verify a BreachScope detached Ed25519 release-manifest signature."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from breachscope.release_signing import (  # noqa: E402
    DEFAULT_SIGNATURE_NAME,
    ReleaseSignatureError,
    verify_release_manifest_signature,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a BreachScope Ed25519 release manifest signature"
    )
    parser.add_argument(
        "--manifest",
        default="dist/release_manifest.json",
        help="Manifest path",
    )
    parser.add_argument(
        "--signature",
        default=None,
        help=(
            "Detached signature JSON path. Defaults to "
            f"{DEFAULT_SIGNATURE_NAME} beside the manifest."
        ),
    )
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument(
        "--public-key",
        default=None,
        help="Trusted URL-safe base64 Ed25519 public key",
    )
    trust.add_argument(
        "--public-key-file",
        default=None,
        help="File containing the trusted URL-safe base64 public key",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = Path(args.manifest)
    signature = (
        Path(args.signature)
        if args.signature
        else manifest.with_name(DEFAULT_SIGNATURE_NAME)
    )
    expected_key = args.public_key
    if args.public_key_file:
        expected_key = Path(args.public_key_file).read_text(
            encoding="utf-8"
        ).strip()

    try:
        result = verify_release_manifest_signature(
            manifest,
            signature,
            expected_public_key_b64=expected_key,
        )
    except (OSError, ReleaseSignatureError) as exc:
        print(f"Release signature verification failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        trust = (
            "trusted-public-key"
            if result["trusted_public_key_supplied"]
            else "embedded-public-key-only"
        )
        print(
            "Release signature verification: PASS "
            f"({trust}) "
            f"public-key-sha256={result['public_key_sha256']}"
        )
        if not result["trusted_public_key_supplied"]:
            print(
                "WARNING: cryptographic consistency is valid, but authenticity "
                "requires comparing the public key/fingerprint with a trusted channel."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
