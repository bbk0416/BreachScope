from __future__ import annotations

import json
from pathlib import Path


PATH = Path("external_baseline/p2_11d_local_account_calibration.json")


def _record():
    return json.loads(PATH.read_text(encoding="utf-8"))


def test_p2_11d_evidence_locks_pinned_sources_and_counts() -> None:
    record = _record()
    benign = record["benign_probe"]
    attack = record["attack_probe"]

    assert benign["asset_sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    assert benign["evtx_files"] == 352
    assert benign["non_sysmon_events"] == 34423
    assert benign["parse_errors"] == 0
    assert benign["security_4720_events"] == 3
    assert benign["candidate_matches"] == 0

    assert attack["pinned_commit"] == (
        "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
    )
    assert attack["parsed_security_events"] == 26
    assert attack["parse_errors"] == 0
    assert attack["security_4720_events"] == 2
    assert attack["candidate_matches"] == 2


def test_p2_11d_claim_boundary_stays_narrow() -> None:
    boundary = _record()["claim_boundary"]
    assert boundary["final_blind_holdout"] is False
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["current_rulepack_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["event_level_precision_recall"] == "NOT_CLAIMED"
