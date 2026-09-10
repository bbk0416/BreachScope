from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


SC_RULE_ID = "R-SERVICE-DISCOVERY-SC-LIST"
NET_RULE_ID = "R-SERVICE-DISCOVERY-NET-START-LIST"


def _rules():
    by_id = {rule.id: rule for rule in load_rules(Path("rules"))}
    return [by_id[SC_RULE_ID], by_id[NET_RULE_ID]]


def _event(
    *,
    image: str,
    command_line: str,
    source: str = "Microsoft-Windows-Sysmon",
    event_id: str = "1",
) -> Event:
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="SERVER002",
        source=source,
        event_id=event_id,
        user="SERVER002\\operator",
        command_line=command_line,
        raw={"Image": image},
    )


def _ids(event: Event) -> set[str]:
    return {finding.rule_id for finding in apply_rules([event], _rules())}


def test_sc_query_listing_matches() -> None:
    event = _event(image=r"C:\Windows\System32\sc.exe", command_line="sc  query ")
    assert _ids(event) == {SC_RULE_ID}


def test_sc_query_state_all_listing_matches() -> None:
    event = _event(
        image=r"C:\Windows\System32\sc.exe",
        command_line="sc  query state= all",
    )
    assert _ids(event) == {SC_RULE_ID}


def test_sc_quoted_absolute_path_listing_matches() -> None:
    event = _event(
        image=r"C:\Windows\System32\sc.exe",
        command_line=r'"C:\Windows\System32\sc.exe" query',
    )
    assert _ids(event) == {SC_RULE_ID}


def test_sc_named_service_query_is_excluded() -> None:
    event = _event(
        image=r"C:\Windows\System32\sc.exe",
        command_line="sc query Spooler",
    )
    assert _ids(event) == set()


def test_sc_non_query_action_is_excluded() -> None:
    event = _event(
        image=r"C:\Windows\System32\sc.exe",
        command_line="sc start Spooler",
    )
    assert _ids(event) == set()


def test_net_start_listing_matches() -> None:
    event = _event(
        image=r"C:\Windows\System32\net.exe",
        command_line="net.exe  start ",
    )
    assert _ids(event) == {NET_RULE_ID}


def test_net1_start_listing_matches() -> None:
    event = _event(
        image=r"C:\Windows\System32\net1.exe",
        command_line=r"C:\Windows\system32\net1  start ",
    )
    assert _ids(event) == {NET_RULE_ID}


def test_net_named_service_start_is_excluded() -> None:
    event = _event(
        image=r"C:\Windows\System32\net.exe",
        command_line="net start Spooler",
    )
    assert _ids(event) == set()


def test_net_stop_is_excluded() -> None:
    event = _event(
        image=r"C:\Windows\System32\net.exe",
        command_line="net stop Spooler",
    )
    assert _ids(event) == set()


def test_wrong_provider_is_excluded() -> None:
    event = _event(
        image=r"C:\Windows\System32\sc.exe",
        command_line="sc query",
        source="Microsoft-Windows-Security-Auditing",
    )
    assert _ids(event) == set()


def test_wrong_event_id_is_excluded() -> None:
    event = _event(
        image=r"C:\Windows\System32\sc.exe",
        command_line="sc query",
        event_id="13",
    )
    assert _ids(event) == set()


def test_rules_do_not_depend_on_atomic_user_or_parent_command() -> None:
    text = " ".join(
        part
        for rule in _rules()
        for part in [rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)]
    )
    assert "admin_test" not in text
    assert "service-list.txt" not in text
    assert "tasklist.exe" not in text
