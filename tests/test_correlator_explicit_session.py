from __future__ import annotations

from datetime import datetime, timedelta, timezone

from breachscope.correlator import _correlate_by_session
from breachscope.schemas import Event


def _event(*, event_id: str, ts: datetime, raw: dict, source: str = "Microsoft-Windows-Security-Auditing") -> Event:
    return Event(
        timestamp=ts.isoformat(),
        host="WIN-A",
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
    assert chains[0].chain_id == "session_0x12345"
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
    assert chains[0].chain_id == "session_77"
