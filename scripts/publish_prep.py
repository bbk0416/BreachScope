#!/usr/bin/env python3
"""Build the final BreachScope public-launch handoff package."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from breachscope.publish import build_publish_prep  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build BreachScope public publish-prep package")
    parser.add_argument("--repo-root", default=str(ROOT), help="Repository root")
    parser.add_argument("--out", default=str(ROOT / "out" / "publish"), help="Output directory")
    parser.add_argument("--clean", action="store_true", help="Delete output directory before building")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF rendering for faster local checks")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only")
    args = parser.parse_args()

    result = build_publish_prep(args.repo_root, args.out, clean=args.clean, render_pdf=not args.no_pdf)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"BreachScope public launch package created: {result['output_dir']}")
        print(f"ZIP: {result['publish_zip_path']}")
        print(f"SHA-256: {result['publish_zip_sha256']}")
        print(f"Project readiness: {result['project_readiness']['score']}/100 ({result['project_readiness']['status']})")
        print(f"Quality gate: {result['quality_gate']['score']}/100 ({result['quality_gate']['status']})")
        print(f"Go-Live: {result['go_live']['score']}/100 ({result['go_live']['status']})")
        print(f"ZIP hygiene: {result['zip_hygiene_status']}")
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
