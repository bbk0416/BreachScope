#!/usr/bin/env python3
"""Run final BreachScope go-live checks against the current environment."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from breachscope.golive import render_markdown, run_go_live_check


def main() -> int:
    parser = argparse.ArgumentParser(description="BreachScope go-live readiness checker")
    parser.add_argument("--root", default=str(ROOT), help="Project root")
    parser.add_argument("--deployment-mode", choices=["local", "production"], help="Override BS_DEPLOYMENT_MODE")
    parser.add_argument("--json", action="store_true", help="Print JSON")
    parser.add_argument("--markdown", action="store_true", help="Print Markdown")
    parser.add_argument("--output", help="Optional output path")
    parser.add_argument("--strict", action="store_true", help="Return non-zero on warnings as well as failures")
    args = parser.parse_args()

    result = run_go_live_check(args.root, deployment_mode=args.deployment_mode)
    if args.json:
        body = json.dumps(result, ensure_ascii=False, indent=2)
    elif args.markdown:
        body = render_markdown(result)
    else:
        lines = [
            f"BreachScope go-live readiness: {result['status']} ({result['score']}/100)",
            f"Deployment mode: {result['deployment_mode']}",
            f"Checks: {result['summary']['passed']} pass, {result['summary']['warnings']} warn, {result['summary']['failed']} fail",
            "",
        ]
        for check in result["checks"]:
            lines.append(f"[{check['status'].upper()}] {check['name']}: {check['message']}")
        lines.append("")
        lines.append("Next steps:")
        for step in result["next_steps"]:
            lines.append(f"- {step}")
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
