from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


RULE_ID = "R-LOCAL-ACCOUNT-4720-NONSYSTEM"


def _rule():
    by_id = {rule.id: rule for rule in load_rules(Path("rules"))}
    return by_id[RULE_ID]


def _event(
    *,
    host: str = "Server002",
    source: str = "Microsoft-Windows-Security-Auditing",
    event_id: str = "4720",
    subject_sid: str | None = "S-1-5-21-111-222-333-1006",
    target_domain: str | None = "SERVER002",
) -> Event:
    raw = {}
    if subject_sid is not None:
        raw["SubjectUserSid"] = subject_sid
    if target_domain is not None:
        raw["TargetDomainName"] = target_domain
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host=host,
        source=source,
        event_id=event_id,
        user="",
        command_line="",
        raw=raw,
    )


def test_non_system_local_account_creation_matches() -> None:
    findings = list(apply_rules([_event()], [_rule()]))
    assert len(findings) == 1
    assert findings[0].rule_id == RULE_ID
    assert findings[0].mitre_technique == "T1136.001"


def test_fqdn_host_short_name_matches() -> None:
    event = _event(host="server002.example.corp", target_domain="SERVER002")
    assert len(list(apply_rules([event], [_rule()]))) == 1


def test_system_created_account_is_excluded() -> None:
    event = _event(subject_sid="S-1-5-18")
    assert list(apply_rules([event], [_rule()])) == []


def test_different_target_domain_is_excluded() -> None:
    event = _event(target_domain="CORP")
    assert list(apply_rules([event], [_rule()])) == []


def test_wrong_event_id_is_excluded() -> None:
    event = _event(event_id="4722")
    assert list(apply_rules([event], [_rule()])) == []


def test_wrong_provider_is_excluded() -> None:
    event = _event(source="Microsoft-Windows-Sysmon")
    assert list(apply_rules([event], [_rule()])) == []


def test_missing_subject_sid_fails_closed() -> None:
    event = _event(subject_sid=None)
    assert list(apply_rules([event], [_rule()])) == []


def test_missing_target_domain_fails_closed() -> None:
    event = _event(target_domain=None)
    assert list(apply_rules([event], [_rule()])) == []


def test_rule_does_not_depend_on_atomic_account_names() -> None:
    rule = _rule()
    text = " ".join(
        [
            rule.id,
            rule.name,
            rule.description,
            rule.pattern,
            str(rule.all_of),
        ]
    )
    assert "T1136.001_CMD" not in text
    assert "T1136.001_PowerShell" not in text
    assert "admin_test" not in text
