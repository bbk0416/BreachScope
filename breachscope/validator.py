from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, Iterable, Tuple
import json


REQUIRED_FIELDS = ("timestamp", "host", "source", "event_id")


def _iter_jsonl_files(input_dir: Path) -> Iterable[Path]:
    for p in sorted(input_dir.rglob("*.jsonl")):
        yield p


def validate_input(input_dir: Path, sample_limit: int = 10000) -> Dict[str, Any]:
    files = list(_iter_jsonl_files(input_dir))
    total_lines = 0
    parsed = 0
    errors: Dict[str, int] = {"json": 0, "missing_fields": 0}
    missing_samples: list[Tuple[Path, int, str]] = []

    for fp in files:
        with fp.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if total_lines >= sample_limit:
                    break
                total_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    errors["json"] += 1
                    continue
                parsed += 1
                missing = [k for k in REQUIRED_FIELDS if k not in obj]
                if missing:
                    errors["missing_fields"] += 1
                    if len(missing_samples) < 10:
                        missing_samples.append((fp, i, ",".join(missing)))

    return {
        "files": len(files),
        "total_lines": total_lines,
        "parsed": parsed,
        "errors": errors,
        "missing_samples": [
            {"file": str(p), "line": ln, "missing": miss} for p, ln, miss in missing_samples
        ],
        "required_fields": list(REQUIRED_FIELDS),
        "limit": sample_limit,
    }

