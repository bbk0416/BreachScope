#!/usr/bin/env python3
"""Run lightweight BreachScope project-readiness checks."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from breachscope.project_readiness import render_markdown, run_project_readiness


def main() -> int:
    parser = argparse.ArgumentParser(description="BreachScope project readiness checker")
    parser.add_argument("--root", default=".", help="Project root to inspect")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown report")
    parser.add_argument("--output", help="Optional output file for JSON/Markdown/text")
    parser.add_argument("--strict", action="store_true", help="Return non-zero on warnings as well as failures")
    args = parser.parse_args()

    result = run_project_readiness(args.root)
    if args.json:
        body = json.dumps(result, ensure_ascii=False, indent=2)
    elif args.markdown:
        body = render_markdown(result)
    else:
        lines = [
            f"BreachScope project readiness: {result['status']} ({result['score']}/100)",
            f"Checks: {result['summary']['passed']} pass, {result['summary']['warnings']} warn, {result['summary']['failed']} fail",
            "",
        ]
        for check in result["checks"]:
            lines.append(f"[{check['status'].upper()}] {check['name']}: {check['message']}")
        body = "\n".join(lines)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(body + "\n", encoding="utf-8")
    print(body)

    if result["summary"]["failed"]:
        return 1
    if args.strict and result["summary"]["warnings"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
