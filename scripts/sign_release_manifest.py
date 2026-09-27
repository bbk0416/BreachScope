#!/usr/bin/env python3
"""Sign a BreachScope release manifest using BS_RELEASE_SIGNING_PRIVATE_KEY."""
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
    sign_release_manifest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign a BreachScope release manifest with Ed25519"
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
    try:
        result = sign_release_manifest(manifest, signature)
    except ReleaseSignatureError as exc:
        print(f"Release signing failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            "Release manifest signed: "
            f"{result['signature_path']} "
            f"public-key-sha256={result['public_key_sha256']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
