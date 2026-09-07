from __future__ import annotations

from datetime import datetime, timedelta, timezone

from breachscope import correlator
from breachscope.schemas import Event, Finding


SESSION_ID = "0x12345"


def _event(*, event_id: str, ts: datetime, record_id: str) -> Event:
    return Event(
        timestamp=ts.isoformat(),
        host="WIN-A",
        source="Microsoft-Windows-Security-Auditing",
        event_id=event_id,
        user="alice",
        command_line="",
        raw={
            "TargetLogonId": SESSION_ID,
            "System": {
                "Channel": "Security",
                "EventRecordID": record_id,
            },
        },
    )


def _session_chain(events, findings=None):
    chains = correlator._correlate_by_session(events, findings or [])
    session_chains = [chain for chain in chains if chain.chain_type == "session"]
    assert len(session_chains) == 1
    return session_chains[0]


def test_duplicate_logon_record_is_one_lifecycle_observation():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon_a = _event(event_id="4624", ts=ts, record_id="100")
    logon_b = _event(event_id="4624", ts=ts, record_id="100")
    logoff = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        record_id="102",
    )

    chain = _session_chain([logon_a, logon_b, logoff])

    assert [event.event_id for event in chain.events] == ["4624", "4634"]
    assert chain.chain_id == "session_win-a_0x12345"
    assert not getattr(chain, "session_instance_id", None)


def test_duplicate_user_initiated_logoff_record_is_not_repeated_in_session_evidence():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon = _event(event_id="4624", ts=ts, record_id="100")
    initiated_a = _event(
        event_id="4647",
        ts=ts + timedelta(minutes=4),
        record_id="101",
    )
    initiated_b = _event(
        event_id="4647",
        ts=ts + timedelta(minutes=4),
        record_id="101",
    )
    logoff = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        record_id="102",
    )

    chain = _session_chain([logon, initiated_a, initiated_b, logoff])

    assert [event.event_id for event in chain.events] == ["4624", "4647", "4634"]
    assert len(chain.events) == 3


def test_duplicate_completed_logoff_record_is_one_lifecycle_observation():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon = _event(event_id="4624", ts=ts, record_id="100")
    logoff_a = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        record_id="102",
    )
    logoff_b = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        record_id="102",
    )

    chain = _session_chain([logon, logoff_a, logoff_b])

    assert [event.event_id for event in chain.events] == ["4624", "4634"]
    assert len(chain.events) == 2


def test_finding_on_discarded_duplicate_copy_remains_attached_by_strong_identity():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon = _event(event_id="4624", ts=ts, record_id="100")
    initiated_a = _event(
        event_id="4647",
        ts=ts + timedelta(minutes=4),
        record_id="101",
    )
    initiated_b = _event(
        event_id="4647",
        ts=ts + timedelta(minutes=4),
        record_id="101",
    )
    logoff = _event(
        event_id="4634",
        ts=ts + timedelta(minutes=5),
        record_id="102",
    )
    finding = Finding(
        rule_id="TEST-DUP-4647",
        rule_name="duplicate identity finding",
        severity="medium",
        mitre_technique=None,
        event=initiated_b,
        matched_value="4647",
    )

    chain = _session_chain(
        [logon, initiated_a, initiated_b, logoff],
        [finding],
    )

    assert [event.event_id for event in chain.events] == ["4624", "4647", "4634"]
    assert chain.findings == [finding]
