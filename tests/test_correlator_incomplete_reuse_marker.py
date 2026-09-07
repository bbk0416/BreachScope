from __future__ import annotations

from datetime import datetime, timedelta, timezone

from breachscope import correlator, scenario
from breachscope.schemas import Event, EventChain


SESSION_ID = "0x12345"


def _event(
    *,
    event_id: str,
    ts: datetime,
    raw: dict | None = None,
    host: str = "WIN-A",
    user: str = "alice",
) -> Event:
    return Event(
        timestamp=ts.isoformat(),
        host=host,
        source="Microsoft-Windows-Security-Auditing",
        event_id=event_id,
        user=user,
        command_line="",
        raw=raw if raw is not None else {"TargetLogonId": SESSION_ID},
    )


def _incomplete_reuse_fixture():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    orphaned_logon = _event(event_id="4624", ts=ts)
    later_logon = _event(event_id="4624", ts=ts + timedelta(days=2))
    later_logoff = _event(
        event_id="4634",
        ts=ts + timedelta(days=2, minutes=5),
    )
    chains = correlator._correlate_by_session(
        [orphaned_logon, later_logon, later_logoff],
        [],
    )
    session_chains = [chain for chain in chains if chain.chain_type == "session"]
    assert len(session_chains) == 1
    return ts, orphaned_logon, later_logon, later_logoff, session_chains[0]


def _activity_chain(ts: datetime, chain_id: str) -> EventChain:
    event = _event(event_id="4688", ts=ts)
    return EventChain(
        chain_id=chain_id,
        events=[event],
        findings=[],
        start_time=event.timestamp,
        end_time=event.timestamp,
        description="activity candidate",
        confidence=0.5,
        chain_type="activity",
    )


def _group_containing(groups, target):
    return next(group for group in groups if target in group)


def test_incomplete_prior_logon_marks_later_valid_session_as_reused():
    _, orphaned_logon, later_logon, later_logoff, session_chain = (
        _incomplete_reuse_fixture()
    )

    assert session_chain.events == [later_logon, later_logoff]
    assert orphaned_logon not in session_chain.events
    assert session_chain.chain_id.startswith("session_win-a_0x12345_")
    assert session_chain.session_instance_id == session_chain.chain_id


def test_activity_near_incomplete_prior_logon_does_not_attach_to_later_session():
    ts, _, _, _, session_chain = _incomplete_reuse_fixture()
    early_activity = _activity_chain(ts + timedelta(minutes=2), "activity_early")

    groups = scenario._bs_p005_partition_chains([session_chain, early_activity])

    assert len(groups) == 2
    assert _group_containing(groups, early_activity) == [early_activity]
    assert _group_containing(groups, session_chain) == [session_chain]


def test_activity_inside_later_valid_session_still_attaches_to_that_lifecycle():
    ts, _, _, _, session_chain = _incomplete_reuse_fixture()
    later_activity = _activity_chain(
        ts + timedelta(days=2, minutes=2),
        "activity_later",
    )

    groups = scenario._bs_p005_partition_chains([later_activity, session_chain])
    joined = _group_containing(groups, later_activity)

    assert len(groups) == 1
    assert session_chain in joined


def test_duplicate_copy_of_same_evtx_logon_record_is_not_treated_as_reuse():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    raw_logon = {
        "TargetLogonId": SESSION_ID,
        "System": {
            "Channel": "Security",
            "EventRecordID": "4242",
        },
    }
    duplicate_a = _event(event_id="4624", ts=ts, raw=dict(raw_logon))
    duplicate_b = _event(event_id="4624", ts=ts, raw=dict(raw_logon))
    logoff = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        raw={
            "TargetLogonId": SESSION_ID,
            "System": {
                "Channel": "Security",
                "EventRecordID": "4243",
            },
        },
    )

    chains = correlator._correlate_by_session([duplicate_a, duplicate_b, logoff], [])
    session_chains = [chain for chain in chains if chain.chain_type == "session"]

    assert len(session_chains) == 1
    assert session_chains[0].chain_id == "session_win-a_0x12345"
    assert not getattr(session_chains[0], "session_instance_id", None)
