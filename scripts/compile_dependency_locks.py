#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGETS = {
    "310": "3.10.21",
    "311": "3.11.16",
    "312": "3.12.14",
}

TARGET_PLATFORM = "x86_64-unknown-linux-gnu"
UV_VERSION = "0.12.8"
EXCLUDE_NEWER = "2026-09-01T00:00:00Z"


def find_uv() -> str:
    uv = shutil.which("uv")
    if uv:
        return uv
    raise SystemExit(
        f"uv is required. Install the pinned resolver with: "
        f"python -m pip install uv=={UV_VERSION}"
    )


def compile_locks(uv_exe: str | None = None) -> None:
    uv = uv_exe or find_uv()

    for suffix, python_version in TARGETS.items():
        output = ROOT / f"requirements-lock-py{suffix}.txt"
        cmd = [
            uv,
            "pip",
            "compile",
            "pyproject.toml",
            "--extra",
            "dev",
            "--python-platform",
            TARGET_PLATFORM,
            "--python-version",
            python_version,
            "--generate-hashes",
            "--exclude-newer",
            EXCLUDE_NEWER,
            "--output-file",
            str(output),
        ]
        print("> " + " ".join(cmd))
        subprocess.run(cmd, check=True, cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compile BreachScope hashed Linux dependency locks for all "
            "supported Python runtimes."
        )
    )
    parser.parse_args()
    compile_locks()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
