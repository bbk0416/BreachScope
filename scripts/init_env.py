#!/usr/bin/env python3
"""Generate a safe BreachScope .env file for first deployment."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from breachscope.bootstrap_env import generate_env_text, write_env_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate BreachScope .env with random secrets")
    parser.add_argument("--template", default=str(ROOT / ".env.example"), help="Template env file")
    parser.add_argument("--output", default=str(ROOT / ".env"), help="Output env path")
    parser.add_argument("--production", action="store_true", help="Set production-safe defaults such as BS_DISABLE_DOCS=1")
    parser.add_argument("--https", action="store_true", help="Set BS_COOKIE_SECURE=1")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing output file")
    parser.add_argument("--print", dest="print_only", action="store_true", help="Print env text instead of writing a file")
    parser.add_argument("--json", action="store_true", help="Print JSON summary")
    args = parser.parse_args()

    if args.print_only:
        body, summary = generate_env_text(args.template, production=args.production, https=args.https)
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        else:
            print(body, end="")
        return 0

    try:
        result = write_env_file(
            args.output,
            args.template,
            production=args.production,
            https=args.https,
            force=args.force,
        )
    except FileExistsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Generated {result['output']} ({result['mode']})")
        print("Next: review the file, then run `docker compose up --build` or `make web`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
