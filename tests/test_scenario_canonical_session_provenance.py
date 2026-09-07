from __future__ import annotations

from types import SimpleNamespace

from breachscope import scenario
from breachscope.canonical import build_canonical_event


def _canonical_event(*, fields: dict[str, str], host: str = "HOST-A"):
    event_dict = {
        "event_id": 4688,
        "source": "Microsoft-Windows-Security-Auditing",
        "host": host,
        "user": "alice",
        "raw": {"event_data": dict(fields)},
    }
    canonical = build_canonical_event(event_dict)

    # Match the real EVTX ingestion shape: EventData is preserved both as a
    # structured mapping and flattened into raw for legacy compatibility.
    raw = dict(fields)
    raw["event_data"] = dict(fields)
    raw["canonical"] = canonical
    return SimpleNamespace(host=host, user="alice", raw=raw)


def _event_with_raw(*, raw: dict, user: str = "alice", host: str = "HOST-A"):
    return SimpleNamespace(host=host, user=user, raw=raw)


def _chain(event):
    return SimpleNamespace(chain_type="activity", events=[event])


def test_subject_derived_canonical_session_is_not_scenario_session_identity():
    event = _canonical_event(fields={"SubjectLogonId": "0x1111"})

    assert event.raw["canonical"]["session"]["id"] == "0x1111"
    assert scenario._bs_p005_scope(event)["sessions"] == set()


def test_subject_derived_canonical_session_cannot_override_generic_session_id():
    event = _canonical_event(
        fields={"SubjectLogonId": "0x1111", "SessionId": "77"}
    )

    # The canonical model retains the actor-side SubjectLogonId context, while
    # scenario correlation must use the explicit compatibility SessionId.
    assert event.raw["canonical"]["session"]["id"] == "0x1111"
    assert scenario._bs_p005_scope(event)["sessions"] == {"77"}


def test_target_derived_canonical_session_remains_authoritative():
    event = _canonical_event(
        fields={"SubjectLogonId": "0x1111", "TargetLogonId": "0x2222"}
    )

    assert event.raw["canonical"]["session"]["id"] == "0x2222"
    assert scenario._bs_p005_scope(event)["sessions"] == {"0x2222"}


def test_canonical_only_normalized_session_remains_supported():
    event = SimpleNamespace(
        host="HOST-A",
        user="alice",
        raw={
            "canonical": {
                "host": {"name": "HOST-A"},
                "session": {"id": "0x3333"},
            }
        },
    )

    assert scenario._bs_p005_scope(event)["sessions"] == {"0x3333"}


def test_target_logon_id_overrides_conflicting_compatibility_session_id():
    event = _event_with_raw(
        raw={
            "TargetLogonId": "0X00002222",
            "SessionId": "0x9999",
            "event_data": {
                "TargetLogonId": "0X00002222",
                "SessionId": "0x9999",
            },
            "canonical": {
                "host": {"name": "HOST-A"},
                "session": {"id": "0x2222"},
            },
        }
    )

    assert scenario._bs_p005_scope(event)["sessions"] == {"0x2222"}


def test_target_logon_id_precedence_crosses_flattened_event_data_copy():
    event = _event_with_raw(
        raw={
            "TargetLogonId": "0x2222",
            "event_data": {"SessionId": "0x9999"},
        }
    )

    assert scenario._bs_p005_scope(event)["sessions"] == {"0x2222"}


def test_conflicting_compatibility_session_cannot_bridge_another_user():
    alice = _chain(
        _event_with_raw(
            user="alice",
            raw={"TargetLogonId": "0x2222", "SessionId": "0x9999"},
        )
    )
    bob = _chain(
        _event_with_raw(
            user="bob",
            raw={"TargetLogonId": "0x9999"},
        )
    )

    groups = scenario._bs_p005_partition_chains([alice, bob])

    assert len(groups) == 2


def test_invalid_target_logon_id_blocks_compatibility_and_canonical_fallback():
    event = _event_with_raw(
        raw={
            "TargetLogonId": "0X0000",
            "SessionId": "0x9999",
            "canonical": {
                "host": {"name": "HOST-A"},
                "session": {"id": "0x9999"},
            },
        }
    )

    assert scenario._bs_p005_scope(event)["sessions"] == set()
