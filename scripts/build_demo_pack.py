#!/usr/bin/env python3
"""Build a shareable BreachScope demo/handoff package."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from breachscope.demo_pack import build_demo_pack  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build BreachScope demo/handoff package")
    parser.add_argument("--repo-root", default=str(ROOT), help="Repository root")
    parser.add_argument("--out", default=str(ROOT / "out" / "demo_pack"), help="Output directory")
    parser.add_argument("--clean", action="store_true", help="Delete output directory before building")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF rendering for faster local checks")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only")
    args = parser.parse_args()

    result = build_demo_pack(args.repo_root, args.out, clean=args.clean, render_pdf=not args.no_pdf)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    demo = result["demo_summary"]
    print(f"BreachScope demo pack created: {result['output_dir']}")
    print(f"ZIP: {result['zip_path']}")
    print(f"SHA-256: {result['zip_sha256']}")
    print(
        "Demo: "
        f"{demo['total_events']} events, {demo['total_findings']} findings, "
        f"risk {demo['risk_score']}/100 ({demo['risk_level']})"
    )
    print(f"Project readiness: {result['project_readiness']['score']}/100")
    print(f"Quality gate: {result['quality_gate']['score']}/100")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
