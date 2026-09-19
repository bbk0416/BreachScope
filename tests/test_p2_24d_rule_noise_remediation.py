from __future__ import annotations

from pathlib import Path

import yaml

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSIS = ROOT / "external_baseline" / "p2_24d_posthoc_rule_noise_diagnosis.yaml"


def _rule(rule_id: str):
    return next(rule for rule in load_rules(ROOT / "rules") if rule.id == rule_id)


def _event(command_line: str) -> Event:
    return Event(
        timestamp="2026-09-19T00:00:00Z",
        host="WS-TEST",
        source="Microsoft-Windows-Sysmon",
        event_id="1",
        command_line=command_line,
        raw={},
    )


def _find(rule_id: str, command_line: str):
    return list(apply_rules([_event(command_line)], [_rule(rule_id)]))


def test_p2_24d_powershell_bypass_ignores_weak_profile_flags() -> None:
    rule = _rule("R-PS-Bypass")
    assert rule.pattern == "-windowstyle hidden|-executionpolicy bypass"

    assert _find("R-PS-Bypass", "powershell.exe -NoProfile -Command Get-Date") == []
    assert _find("R-PS-Bypass", "powershell.exe -NOP -Command Get-Date") == []

    hidden = _find(
        "R-PS-Bypass",
        "powershell.exe -NoProfile -WindowStyle Hidden -Command Write-Output test",
    )
    bypass = _find(
        "R-PS-Bypass",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File script.ps1",
    )
    assert len(hidden) == 1
    assert hidden[0].matched_value.lower() == "-windowstyle hidden"
    assert len(bypass) == 1
    assert bypass[0].matched_value.lower() == "-executionpolicy bypass"


def test_p2_24d_screen_capture_drops_generic_screenshot_substring() -> None:
    rule = _rule("R-SCREENSHOT-Capture")
    assert rule.pattern == "copyfromscreen|graphics.copyfromscreen|bitblt"

    edge = "msedgewebview2.exe --disable-features=msEdgeScreenshotUI,msEdgeWebCapture"
    assert _find("R-SCREENSHOT-Capture", edge) == []

    capture = _find(
        "R-SCREENSHOT-Capture",
        "powershell.exe Add-Type -AssemblyName System.Drawing; Graphics.CopyFromScreen(0,0,0,0,0)",
    )
    assert len(capture) == 1


def test_p2_24d_lsass_dump_requires_dump_context_not_process_name() -> None:
    rule = _rule("R-LSASS-Dump")
    assert rule.pattern == "comsvcs.dll, MiniDump|sekurlsa::logonpasswords|procdump -ma lsass"

    assert _find("R-LSASS-Dump", r"C:\Windows\System32\lsass.exe") == []

    procdump = _find(
        "R-LSASS-Dump",
        r"procdump -ma lsass.exe C:\Temp\lsass.dmp",
    )
    sekurlsa = _find(
        "R-LSASS-Dump",
        r"cmd.exe /c mimikatz sekurlsa::logonpasswords",
    )
    assert len(procdump) == 1
    assert len(sekurlsa) == 1


def test_p2_24d_posthoc_diagnosis_keeps_claim_boundary() -> None:
    row = yaml.safe_load(DIAGNOSIS.read_text(encoding="utf-8"))
    assert row["analysis_class"] == "POST_HOC_DIAGNOSTIC_NOT_FRESH_EVALUATION"
    assert row["diagnostic_method"]["detector_rerun"] is False
    assert row["diagnostic_method"]["canonical_result_modified"] is False
    assert row["diagnostic_method"]["canonical_rule_counts_reproduced_by_raw_predicates"] is True

    remediation = row["remediation"]
    assert remediation["remediation_id"] == "p2-24d-rule-noise-remediation"
    assert remediation["detector_repo_commit"] == "66f5d2e0061ea34113038a712597113a6df7bd63"
    assert remediation["from_rules_tree_sha256"] == (
        "93c1baf1af676eb9c1e4c7dd7238b8a16f67e96f2fdf7320ebe0aa8053c0d075"
    )
    assert remediation["to_rules_tree_sha256"] == (
        "ac5b6f1db7af2208910e9a7954b414d21c6ef019dfcdf29ddfdd566cd77a9326"
    )
    assert remediation["rule_file_git_blob_sha1"] == "ef1e026256eb1e66f992459166ede963424606df"
    assert remediation["fresh_attack_revalidation"] == "NOT_RUN"
    assert remediation["fresh_benign_revalidation"] == "NOT_RUN"

    diagnosis = row["rule_diagnosis"]
    assert diagnosis["R-PS-Bypass"]["first_match_noprofile"] == 1824
    assert diagnosis["R-PROCESS-Discovery"]["get_process"] == 498
    assert diagnosis["R-SCREENSHOT-Capture"]["generic_screenshot_token"] == 11
    assert diagnosis["R-LSASS-Dump"]["canonical_findings"] == 1

    posthoc = row["posthoc_counterfactual_after_three_narrow_changes"]
    assert posthoc["estimated_flagged_events"] == 570
    assert posthoc["estimated_flagged_event_percent"] == 1.6505472867319164
    assert posthoc["estimated_reduction_from_p2_24c_flagged_events"] == 1834
    assert posthoc["estimated_reduction_percent"] == 76.28951747088186

    boundary = row["claim_boundary"]
    assert boundary["p2_24c_is_now_development_data"] is True
    assert boundary["counterfactual_is_fresh_measurement"] is False
    assert boundary["counterfactual_is_independent_validation"] is False
    assert boundary["flagged_events_are_confirmed_false_positives"] is False
    assert boundary["confirmed_false_positives"] == "NOT_CLAIMED"
    assert boundary["general_fresh_full_benign_fpr_for_current_rulepack"] == "NOT_CLAIMED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
