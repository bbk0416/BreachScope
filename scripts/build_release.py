#!/usr/bin/env python3
"""Build BreachScope release artifacts.

Creates:
- dist/breachscope-<version>-source.zip
- dist/SHA256SUMS.txt
- dist/release_manifest.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from breachscope.release import build_release_bundle, clean_dist  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build BreachScope release artifacts")
    parser.add_argument("--repo-root", default=str(ROOT), help="Repository root")
    parser.add_argument("--dist", default=str(ROOT / "dist"), help="Output dist directory")
    parser.add_argument("--clean", action="store_true", help="Delete dist directory before building")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.clean:
        clean_dist(args.dist)
    result = build_release_bundle(args.repo_root, args.dist)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print(f"BreachScope release bundle created in {result['dist_dir']}")
    for artifact in result["artifacts"]:
        print(f"- {Path(artifact['path']).name} ({artifact['size_bytes']} bytes) sha256={artifact['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
