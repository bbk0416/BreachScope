from __future__ import annotations

from types import SimpleNamespace

import pytest

from breachscope import correlator, scenario, scenario_user_scope


INVALID_SESSION_IDS = ("0", "0x0", "-", "none", "NULL", 0)


def _event(host: str, user: str, session, *, canonical: bool = True):
    raw = {"TargetLogonId": session}
    if canonical:
        raw["canonical"] = {
            "host": {"name": host},
            "session": {"id": session},
        }
    return SimpleNamespace(host=host, user=user, raw=raw)


def _canonical_only_event(host: str, user: str, session):
    return SimpleNamespace(
        host=host,
        user=user,
        raw={
            "canonical": {
                "host": {"name": host},
                "session": {"id": session},
            }
        },
    )


def _chain(host: str, user: str, session):
    return SimpleNamespace(
        chain_type="activity",
        events=[_event(host, user, session)],
    )


def _finding(host: str, user: str, session):
    return SimpleNamespace(event=_event(host, user, session))


@pytest.mark.parametrize("session_id", INVALID_SESSION_IDS)
def test_invalid_target_logon_id_does_not_define_scenario_session(session_id):
    event_scope = scenario._bs_p005_scope(_event("HOST-A", "alice", session_id))

    assert event_scope["sessions"] == set()


@pytest.mark.parametrize("session_id", INVALID_SESSION_IDS)
def test_invalid_canonical_only_id_does_not_define_scenario_session(session_id):
    event_scope = scenario._bs_p005_scope(
        _canonical_only_event("HOST-A", "alice", session_id)
    )

    assert event_scope["sessions"] == set()


def test_invalid_session_id_cannot_bridge_different_users_on_same_host():
    alice = _chain("HOST-A", "alice", "0x0")
    bob = _chain("HOST-A", "bob", "0x0")

    groups = scenario._bs_p005_partition_chains([alice, bob])

    assert len(groups) == 2


def test_invalid_session_finding_cannot_strengthen_other_user_component():
    component = scenario._bs_p005_component_scope(
        [_chain("HOST-A", "alice", "0x0")]
    )
    findings = [
        _finding("HOST-A", "alice", "0x0"),
        _finding("HOST-A", "bob", "0x0"),
    ]

    selected = scenario._bs_p005_filter_findings(findings, component)

    assert len(selected) == 1
    assert scenario._bs_p005_scope(selected[0])["users"] == {"alice"}


def test_valid_target_logon_id_remains_authoritative():
    event_scope = scenario._bs_p005_scope(_event("HOST-A", "alice", "0x1234"))

    assert event_scope["sessions"] == {"0x1234"}


def test_scenario_invalid_id_contract_matches_correlator():
    assert (
        scenario_user_scope._BS_P207S_INVALID_SESSION_IDS
        == correlator._BS_P207I_INVALID_SESSION_IDS
    )
