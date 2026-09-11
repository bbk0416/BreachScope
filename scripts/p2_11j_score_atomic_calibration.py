#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import p2_11h_score_atomic_calibration as base

DETECTOR_COMMIT = "357b7ea88c5949d899ec637c95f56bad61605f3c"
EXPECTED_RULE_TREE = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
EXPECTED_RULE_COUNT = 66

base.DETECTOR_COMMIT = DETECTOR_COMMIT
base.EXPECTED_RULE_TREE = EXPECTED_RULE_TREE
base.EXPECTED_RULE_COUNT = EXPECTED_RULE_COUNT


def make_labels(index_path: Path, labels_path: Path) -> str:
    count = 0
    with index_path.open("r", encoding="utf-8") as src, labels_path.open(
        "w", encoding="utf-8", newline="\n"
    ) as dst:
        for line in src:
            if not line.strip():
                continue
            row = json.loads(line)
            dst.write(json.dumps({
                "event_key": row["event_key"],
                "label": "ignore",
                "expected_techniques": [],
                "notes": "P2-11J external calibration; no independent event-level ground truth.",
            }, ensure_ascii=False) + "\n")
            count += 1
    if count <= 0:
        raise RuntimeError("index produced zero events")
    return base.sha256(labels_path)


base.make_labels = make_labels


def _out_root_from_argv() -> Path:
    try:
        idx = sys.argv.index("--out-root")
        return Path(sys.argv[idx + 1]).resolve()
    except (ValueError, IndexError) as exc:
        raise RuntimeError("--out-root is required") from exc


def main() -> int:
    out_root = _out_root_from_argv()
    rc = base.main()
    if rc != 0:
        return rc
    aggregate_path = out_root / "aggregate-result.json"
    data = json.loads(aggregate_path.read_text(encoding="utf-8"))
    data["schema"] = "breachscope.p2_11j_external_calibration_result.v1"
    data["change_class"] = "networkprovider_credential_capture_setup_rule_addition"
    data["claim_boundary"]["note"] = (
        "Same public Atomic-EVTX scenarios were already observed in P2-11B and used for calibration. "
        "P2-11J adds generic NetworkProvider order plus provider-DLL registration telemetry; this remains external calibration only."
    )
    aggregate_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(data, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
