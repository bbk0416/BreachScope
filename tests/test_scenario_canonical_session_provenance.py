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
