from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]


def _rules():
    return load_rules(ROOT / "rules")


def _event(
    object_name: str,
    *,
    object_type: str = "SAM_GROUP",
    object_server: str = "Security Account Manager",
    event_id: str = "4661",
    source: str = "Microsoft-Windows-Security-Auditing",
) -> Event:
    return Event(
        timestamp="2026-09-08T00:00:00Z",
        host="dc1.example.test",
        source=source,
        event_id=event_id,
        command_line="",
        raw={
            "ObjectName": object_name,
            "ObjectType": object_type,
            "ObjectServer": object_server,
        },
    )


def _has_new_rule(event: Event) -> bool:
    return any(
        finding.rule_id == "R-DOMAIN-ADMINS-4661"
        for finding in apply_rules([event], _rules())
    )


def test_domain_admins_group_sid_matches() -> None:
    event = _event("S-1-5-21-1587066498-1489273250-1035260531-512")
    findings = list(apply_rules([event], _rules()))
    matches = [finding for finding in findings if finding.rule_id == "R-DOMAIN-ADMINS-4661"]

    assert len(matches) == 1
    assert matches[0].mitre_technique == "T1087.002"


def test_domain_users_rid_does_not_match() -> None:
    assert not _has_new_rule(_event("S-1-5-21-1587066498-1489273250-1035260531-513"))


def test_sam_user_object_does_not_match() -> None:
    assert not _has_new_rule(
        _event("S-1-5-21-1587066498-1489273250-1035260531-512", object_type="SAM_USER")
    )


def test_wrong_event_id_does_not_match() -> None:
    assert not _has_new_rule(
        _event("S-1-5-21-1587066498-1489273250-1035260531-512", event_id="4656")
    )


def test_wrong_provider_does_not_match() -> None:
    assert not _has_new_rule(
        _event(
            "S-1-5-21-1587066498-1489273250-1035260531-512",
            source="Microsoft-Windows-Sysmon",
        )
    )


def test_wrong_object_server_does_not_match() -> None:
    assert not _has_new_rule(
        _event(
            "S-1-5-21-1587066498-1489273250-1035260531-512",
            object_server="Other Server",
        )
    )
