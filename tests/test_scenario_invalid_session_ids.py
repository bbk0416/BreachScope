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


def _conflicting_event(
    host: str,
    user: str,
    target_session,
    alias_session,
    *,
    nested_alias: bool = False,
):
    raw = {
        "TargetLogonId": target_session,
        "canonical": {
            "host": {"name": host},
            "session": {"id": target_session},
        },
    }
    if nested_alias:
        raw["event_data"] = {"SessionId": alias_session}
    else:
        raw["SessionId"] = alias_session
    return SimpleNamespace(host=host, user=user, raw=raw)


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


def test_equivalent_hex_session_ids_share_one_scenario_identity():
    padded = _chain("HOST-A", "alice", "0X00012345")
    canonical = _chain("HOST-A", "alice", "0x12345")

    padded_scope = scenario._bs_p005_scope(padded)
    canonical_scope = scenario._bs_p005_scope(canonical)
    groups = scenario._bs_p005_partition_chains([padded, canonical])

    assert padded_scope["sessions"] == {"0x12345"}
    assert canonical_scope["sessions"] == {"0x12345"}
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_equivalent_hex_session_finding_matches_component():
    component = scenario._bs_p005_component_scope(
        [_chain("HOST-A", "alice", "0x12345")]
    )
    finding = _finding("HOST-A", "alice", "0X00012345")

    selected = scenario._bs_p005_filter_findings([finding], component)

    assert selected == [finding]


def test_canonical_session_can_match_zero_padded_raw_target_logon_id():
    event = SimpleNamespace(
        host="HOST-A",
        user="alice",
        raw={
            "TargetLogonId": "0X00012345",
            "canonical": {
                "host": {"name": "HOST-A"},
                "session": {"id": "0x12345"},
            },
        },
    )

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == {"0x12345"}


def test_zero_padded_zero_hex_session_is_invalid():
    event_scope = scenario._bs_p005_scope(_event("HOST-A", "alice", "0X0000"))

    assert event_scope["sessions"] == set()


def test_target_logon_id_precedes_conflicting_session_alias():
    event = _conflicting_event("HOST-A", "alice", "0x1111", "0x2222")

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == {"0x1111"}


def test_nested_event_data_session_alias_cannot_override_target_logon_id():
    event = _conflicting_event(
        "HOST-A",
        "alice",
        "0x1111",
        "0x2222",
        nested_alias=True,
    )

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == {"0x1111"}


def test_conflicting_session_alias_cannot_bridge_different_users():
    alice = SimpleNamespace(
        chain_type="session",
        events=[_conflicting_event("HOST-A", "alice", "0x1111", "0x2222")],
    )
    bob = _chain("HOST-A", "bob", "0x2222")

    groups = scenario._bs_p005_partition_chains([alice, bob])

    assert len(groups) == 2


def test_conflicting_session_alias_finding_does_not_match_alias_component():
    component = scenario._bs_p005_component_scope(
        [_chain("HOST-A", "bob", "0x2222")]
    )
    finding = SimpleNamespace(
        event=_conflicting_event("HOST-A", "alice", "0x1111", "0x2222")
    )

    selected = scenario._bs_p005_filter_findings([finding], component)

    assert selected == []


def test_invalid_target_logon_id_does_not_fall_back_to_valid_session_alias():
    event = _conflicting_event("HOST-A", "alice", "0x0", "0x2222")

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == set()


def test_session_alias_remains_supported_without_target_logon_id():
    event = SimpleNamespace(
        host="HOST-A",
        user="alice",
        raw={
            "SessionId": "0X00002222",
            "canonical": {
                "host": {"name": "HOST-A"},
                "session": {"id": "0x2222"},
            },
        },
    )

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == {"0x2222"}
