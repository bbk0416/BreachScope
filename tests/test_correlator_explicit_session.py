from __future__ import annotations

from datetime import datetime, timedelta, timezone

from breachscope.correlator import _correlate_by_session
from breachscope.schemas import Event


def _event(
    *,
    event_id: str,
    ts: datetime,
    raw: dict,
    host: str = "WIN-A",
    source: str = "Microsoft-Windows-Security-Auditing",
) -> Event:
    return Event(
        timestamp=ts.isoformat(),
        host=host,
        source=source,
        event_id=event_id,
        user="alice",
        command_line="",
        raw=raw,
    )


def test_same_host_user_without_explicit_session_id_does_not_create_session_chain():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    first = _event(event_id="4688", ts=ts, raw={})
    second = _event(event_id="4688", ts=ts + timedelta(hours=12), raw={})

    assert _correlate_by_session([first, second], []) == []


def test_nearby_same_host_user_is_bounded_activity_not_session():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    first = _event(event_id="4688", ts=ts, raw={})
    second = _event(event_id="4688", ts=ts + timedelta(minutes=5), raw={})

    chains = _correlate_by_session([first, second], [])

    assert len(chains) == 1
    assert chains[0].chain_type == "activity"
    assert not chains[0].chain_id.startswith("session_")
    assert chains[0].events == [first, second]


def test_success_logon_and_logoff_group_by_target_logon_id_not_subject_logon_id():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon = _event(
        event_id="4624",
        ts=ts,
        raw={"SubjectLogonId": "0x3e7", "TargetLogonId": "0x12345"},
    )
    logoff = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        raw={"SubjectLogonId": "0x999", "TargetLogonId": "0x12345"},
    )

    chains = _correlate_by_session([logon, logoff], [])

    assert len(chains) == 1
    assert chains[0].chain_id == "session_win-a_0x12345"
    assert chains[0].events == [logon, logoff]


def test_failed_logons_do_not_form_session_chains():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    first = _event(event_id="4625", ts=ts, raw={"TargetLogonId": "0x0"})
    second = _event(
        event_id="4625",
        ts=ts + timedelta(seconds=10),
        raw={"TargetLogonId": "0x0"},
    )

    assert _correlate_by_session([first, second], []) == []


def test_explicit_session_id_remains_supported_for_success_session_events():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon = _event(event_id="4624", ts=ts, raw={"SessionId": "77"})
    logoff = _event(event_id="4634", ts=ts + timedelta(seconds=30), raw={"SessionId": "77"})

    chains = _correlate_by_session([logon, logoff], [])

    assert len(chains) == 1
    assert chains[0].chain_id == "session_win-a_77"


def test_same_session_id_on_different_hosts_forms_separate_session_chains():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    events = [
        _event(
            event_id="4624",
            ts=ts,
            raw={"TargetLogonId": "0x12345"},
            host="WIN-A",
        ),
        _event(
            event_id="4634",
            ts=ts + timedelta(minutes=1),
            raw={"TargetLogonId": "0x12345"},
            host="WIN-A",
        ),
        _event(
            event_id="4624",
            ts=ts + timedelta(minutes=2),
            raw={"TargetLogonId": "0x12345"},
            host="WIN-B",
        ),
        _event(
            event_id="4634",
            ts=ts + timedelta(minutes=3),
            raw={"TargetLogonId": "0x12345"},
            host="WIN-B",
        ),
    ]

    chains = _correlate_by_session(events, [])
    session_chains = [chain for chain in chains if chain.chain_type == "session"]

    assert len(session_chains) == 2
    assert {chain.chain_id for chain in session_chains} == {
        "session_win-a_0x12345",
        "session_win-b_0x12345",
    }
    assert {tuple(event.host for event in chain.events) for chain in session_chains} == {
        ("WIN-A", "WIN-A"),
        ("WIN-B", "WIN-B"),
    }


def test_explicit_session_without_host_does_not_form_session_chain():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon = _event(
        event_id="4624",
        ts=ts,
        raw={"TargetLogonId": "0x12345"},
        host="",
    )
    logoff = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=1),
        raw={"TargetLogonId": "0x12345"},
        host="",
    )

    assert _correlate_by_session([logon, logoff], []) == []


def test_reused_session_id_on_same_host_forms_separate_lifecycle_chains():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    first_logon = _event(
        event_id="4624",
        ts=ts,
        raw={"TargetLogonId": "0x12345"},
    )
    first_logoff = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        raw={"TargetLogonId": "0x12345"},
    )
    second_logon = _event(
        event_id="4624",
        ts=ts + timedelta(days=2),
        raw={"TargetLogonId": "0x12345"},
    )
    second_logoff = _event(
        event_id="4634",
        ts=ts + timedelta(days=2, minutes=5),
        raw={"TargetLogonId": "0x12345"},
    )

    chains = _correlate_by_session(
        [first_logon, first_logoff, second_logon, second_logoff], []
    )
    session_chains = [chain for chain in chains if chain.chain_type == "session"]

    assert len(session_chains) == 2
    assert {tuple(chain.events) for chain in session_chains} == {
        (first_logon, first_logoff),
        (second_logon, second_logoff),
    }
    assert len({chain.chain_id for chain in session_chains}) == 2
    assert all(
        chain.chain_id.startswith("session_win-a_0x12345_")
        for chain in session_chains
    )


def test_new_logon_starts_new_lifecycle_when_previous_logoff_is_missing():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    orphaned_logon = _event(
        event_id="4624",
        ts=ts,
        raw={"TargetLogonId": "0x12345"},
    )
    later_logon = _event(
        event_id="4624",
        ts=ts + timedelta(days=2),
        raw={"TargetLogonId": "0x12345"},
    )
    later_logoff = _event(
        event_id="4634",
        ts=ts + timedelta(days=2, minutes=5),
        raw={"TargetLogonId": "0x12345"},
    )

    chains = _correlate_by_session([orphaned_logon, later_logon, later_logoff], [])
    session_chains = [chain for chain in chains if chain.chain_type == "session"]

    assert len(session_chains) == 1
    assert session_chains[0].events == [later_logon, later_logoff]
    assert orphaned_logon not in session_chains[0].events
