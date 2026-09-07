from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from breachscope import scenario
from breachscope.correlator import _correlate_by_session
from breachscope.schemas import Event


MALFORMED_HEX_SESSION_IDS = (
    "0x",
    "0xZZZ",
    "0X12-34",
    "0x+1",
)


def _security_event(event_id: str, ts: datetime, session_id: str) -> Event:
    return Event(
        timestamp=ts.isoformat(),
        host="WIN-A",
        source="Microsoft-Windows-Security-Auditing",
        event_id=event_id,
        user="alice",
        command_line="",
        raw={"TargetLogonId": session_id},
    )


def _scenario_event(host: str, user: str, session_id: str):
    return SimpleNamespace(
        host=host,
        user=user,
        raw={
            "TargetLogonId": session_id,
            "canonical": {
                "host": {"name": host},
                "session": {"id": session_id},
            },
        },
    )


@pytest.mark.parametrize("session_id", MALFORMED_HEX_SESSION_IDS)
def test_malformed_hex_target_logon_id_does_not_form_explicit_session(session_id):
    ts = datetime(2026, 9, 8, tzinfo=timezone.utc)
    logon = _security_event("4624", ts, session_id)
    logoff = _security_event("4634", ts + timedelta(minutes=1), session_id)

    assert _correlate_by_session([logon, logoff], []) == []


@pytest.mark.parametrize("session_id", MALFORMED_HEX_SESSION_IDS)
def test_malformed_hex_target_logon_id_does_not_define_scenario_session(session_id):
    event_scope = scenario._bs_p005_scope(
        _scenario_event("HOST-A", "alice", session_id)
    )

    assert event_scope["sessions"] == set()


def test_malformed_hex_session_id_cannot_bridge_different_users_on_same_host():
    alice = SimpleNamespace(
        chain_type="session",
        events=[_scenario_event("HOST-A", "alice", "0xZZZ")],
    )
    bob = SimpleNamespace(
        chain_type="session",
        events=[_scenario_event("HOST-A", "bob", "0xZZZ")],
    )

    groups = scenario._bs_p005_partition_chains([alice, bob])

    assert len(groups) == 2


def test_plain_compatibility_session_alias_remains_supported():
    event = SimpleNamespace(
        host="HOST-A",
        user="alice",
        raw={
            "SessionId": "77",
            "canonical": {
                "host": {"name": "HOST-A"},
                "session": {"id": "77"},
            },
        },
    )

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == {"77"}
