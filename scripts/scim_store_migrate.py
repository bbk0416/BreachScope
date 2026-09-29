#!/usr/bin/env python3
"""Source-checkout wrapper for the packaged SCIM migration CLI."""
from __future__ import annotations

import sys
from pathlib import Path


def _main() -> int:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from breachscope.scim_migrate import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_main())
