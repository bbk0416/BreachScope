import json
import re
from pathlib import Path

from scripts.brawl_posthoc_diagnose import _bsf_event_summary, _sanitize_text


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "external_baseline" / "results" / "brawl_posthoc_b306aa7" / "result.json"


def test_posthoc_sanitizer_redacts_brawl_credentials():
    assert (
        _sanitize_text('wmic /node:"host" /password:"secret" process call create "x"')
        == 'wmic /node:"host" /password:"<redacted>" process call create "x"'
    )
    assert (
        _sanitize_text(r'net use \\host\C$ secret /user:domain\user')
        == r'net use \\host\C$ <redacted> /user:domain\user'
    )


def test_bsf_event_summary_keeps_shape_but_not_password():
    summary = _bsf_event_summary(
        {
            "id": "event-1",
            "host": "host",
            "object": "process",
            "action": "create",
            "command_line": 'wmic /password:"secret" process call create "x"',
            "unrelated": "drop-me",
        }
    )

    assert summary["object"] == "process"
    assert summary["action"] == "create"
    assert summary["command_line"] == 'wmic /password:"<redacted>" process call create "x"'
    assert "unrelated" not in summary


def test_posthoc_result_preserves_sealed_result_and_classifies_all_pairs():
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert result["analysis_id"] == "brawl-posthoc-miss-diagnosis-v1"
    assert result["status"] == "POSTHOC_COMPLETED"
    assert result["canonical_analysis_id"] == "brawl-independent-attack-step-technique-holdout-v1"
    assert result["canonical_pair_hits"] == 0
    assert result["canonical_pair_misses"] == 133
    assert result["canonical_pair_errors"] == 0

    assert result["finding_count"] == 44
    assert result["findings_by_rule"] == {
        "R-MSBUILD-InlineTask": 29,
        "R-NET-View-Share": 15,
    }
    assert result["findings_by_technique"] == {
        "T1127.001": 29,
        "T1135": 15,
    }

    assert result["pair_classifications"] == {
        "TELEMETRY_PRESENT_NO_EXPECTED_TECHNIQUE_FINDING": 96,
        "NO_CURRENT_RULE_COVERAGE": 34,
        "NO_NORMALIZED_TELEMETRY_IN_BSF_WINDOW": 3,
    }
    assert sum(result["pair_classifications"].values()) == 133

    claims = result["claim_boundaries"]
    assert claims["canonical_result_modified"] is False
    assert claims["canonical_rerun"] is False
    assert claims["posthoc_only"] is True
    assert claims["event_level_recall"] == "NOT_CLAIMED"


def test_posthoc_result_contains_no_unredacted_brawl_password_arguments():
    text = RESULT.read_text(encoding="utf-8")

    assert not re.search(r'(?i)/password\s*:\s*"(?!<redacted>)', text)
    assert not re.search(
        r'(?i)net\"?\s+use\s+\\\\[^\s]+\s+(?!<redacted>)\S+\s+/user:',
        text,
    )

def test_posthoc_canonical_lock_copy_matches_expected_permanent_lock():
    lock = ROOT / "external_baseline" / "locks" / "BRAWL_ATTACK_STEP_TECHNIQUE_HOLDOUT_V1.lock"
    data = lock.read_bytes()

    import hashlib

    assert hashlib.sha256(data).hexdigest() == "8ae204ed88cdff01b69bd243c69183d440354bfcc278fb55b9dcb6ffa6b6b965"
    payload = json.loads(data.decode("utf-8"))
    assert payload["analysis_id"] == "brawl-independent-attack-step-technique-holdout-v1"
