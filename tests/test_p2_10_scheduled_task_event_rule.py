from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]


def _rules():
    return load_rules(ROOT / "rules")


def _event(event_id: str, source: str, command_line: str | None = None) -> Event:
    return Event(
        timestamp="2026-09-08T00:00:00Z",
        host="host1",
        source=source,
        event_id=event_id,
        command_line=command_line,
        raw={},
    )


def test_security_4698_matches_scheduled_task_event_rule_without_command_line() -> None:
    findings = list(
        apply_rules(
            [_event("4698", "Microsoft-Windows-Security-Auditing")],
            _rules(),
        )
    )

    matches = [finding for finding in findings if finding.rule_id == "R-SCHTASK-4698"]
    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1053.005"
    assert matches[0].matched_value == "4698"


def test_4698_from_wrong_provider_does_not_match_new_rule() -> None:
    findings = list(apply_rules([_event("4698", "Other-Provider")], _rules()))
    assert all(finding.rule_id != "R-SCHTASK-4698" for finding in findings)


def test_security_4699_does_not_match_creation_rule() -> None:
    findings = list(
        apply_rules(
            [_event("4699", "Microsoft-Windows-Security-Auditing")],
            _rules(),
        )
    )
    assert all(finding.rule_id != "R-SCHTASK-4698" for finding in findings)


def test_existing_schtasks_command_line_rule_still_matches() -> None:
    findings = list(
        apply_rules(
            [_event("1", "Microsoft-Windows-Sysmon", "schtasks /create /tn Demo /tr calc.exe")],
            _rules(),
        )
    )
    assert any(finding.rule_id == "R-SCHTASKS-Create" for finding in findings)
