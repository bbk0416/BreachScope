from __future__ import annotations

from datetime import datetime, timedelta, timezone

from breachscope import correlator, scenario
from breachscope.schemas import Event, EventChain, Finding


def _event(
    *,
    event_id: str,
    ts: datetime,
    session_id: str = "0x12345",
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
        raw={"TargetLogonId": session_id},
    )


def _activity_chain(ts: datetime, chain_id: str = "activity") -> EventChain:
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


def _reused_session_fixture():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    first_logon = _event(event_id="4624", ts=ts)
    first_logoff = _event(event_id="4634", ts=ts + timedelta(minutes=5))
    second_logon = _event(event_id="4624", ts=ts + timedelta(days=2))
    second_logoff = _event(
        event_id="4634",
        ts=ts + timedelta(days=2, minutes=5),
    )
    events = [first_logon, first_logoff, second_logon, second_logoff]
    chains = correlator._correlate_by_session(events, [])
    session_chains = sorted(
        [chain for chain in chains if chain.chain_type == "session"],
        key=lambda chain: chain.start_time,
    )
    return session_chains, events


def _finding(event: Event, rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=rule_id,
        severity="high",
        mitre_technique="T1078",
        event=event,
        matched_value=event.event_id,
    )


def _group_containing(groups, target):
    return next(group for group in groups if target in group)


def test_reused_logon_id_exposes_distinct_lifecycle_instances():
    session_chains, _ = _reused_session_fixture()

    assert len(session_chains) == 2
    assert all(
        getattr(chain, "session_instance_id", None)
        for chain in session_chains
    )
    assert len(
        {chain.session_instance_id for chain in session_chains}
    ) == 2
    assert all(
        chain.session_instance_id == chain.chain_id
        for chain in session_chains
    )


def test_reused_logon_id_lifecycles_stay_separate_in_scenario_partition():
    session_chains, _ = _reused_session_fixture()

    groups = scenario._bs_p005_partition_chains(session_chains)

    assert len(groups) == 2
    assert all(len(group) == 1 for group in groups)


def test_activity_between_reused_lifecycles_stays_unassigned():
    session_chains, _ = _reused_session_fixture()
    first = session_chains[0]
    second = session_chains[1]
    bridge = _activity_chain(
        datetime(2026, 9, 8, tzinfo=timezone.utc),
        "activity_between",
    )

    groups = scenario._bs_p005_partition_chains([first, bridge, second])

    assert len(groups) == 3
    assert _group_containing(groups, bridge) == [bridge]
    assert not any(first in group and second in group for group in groups)


def test_activity_inside_second_lifecycle_joins_second_not_first():
    session_chains, _ = _reused_session_fixture()
    first = session_chains[0]
    second = session_chains[1]
    activity = _activity_chain(
        datetime(2026, 9, 9, 0, 2, tzinfo=timezone.utc),
        "activity_second",
    )

    groups = scenario._bs_p005_partition_chains([first, activity, second])
    activity_group = _group_containing(groups, activity)

    assert len(groups) == 2
    assert second in activity_group
    assert first not in activity_group


def test_activity_inside_first_lifecycle_joins_first_regardless_of_input_order():
    session_chains, _ = _reused_session_fixture()
    first = session_chains[0]
    second = session_chains[1]
    activity = _activity_chain(
        datetime(2026, 9, 7, 0, 2, tzinfo=timezone.utc),
        "activity_first",
    )

    groups = scenario._bs_p005_partition_chains([second, activity, first])
    activity_group = _group_containing(groups, activity)

    assert len(groups) == 2
    assert first in activity_group
    assert second not in activity_group


def test_chain_overlapping_multiple_reused_lifecycles_stays_unassigned():
    session_chains, _ = _reused_session_fixture()
    first = session_chains[0]
    second = session_chains[1]
    first_event = _event(
        event_id="4688",
        ts=datetime(2026, 9, 7, 0, 2, tzinfo=timezone.utc),
    )
    second_event = _event(
        event_id="4688",
        ts=datetime(2026, 9, 9, 0, 2, tzinfo=timezone.utc),
    )
    ambiguous = EventChain(
        chain_id="activity_ambiguous",
        events=[first_event, second_event],
        findings=[],
        start_time=first_event.timestamp,
        end_time=second_event.timestamp,
        description="ambiguous lifecycle activity",
        confidence=0.5,
        chain_type="activity",
    )

    groups = scenario._bs_p005_partition_chains([first, ambiguous, second])

    assert len(groups) == 3
    assert _group_containing(groups, ambiguous) == [ambiguous]


def test_reused_lifecycle_component_only_accepts_its_own_event_findings():
    session_chains, events = _reused_session_fixture()
    first_logon, _, second_logon, _ = events
    component = scenario._bs_p005_component_scope([session_chains[0]])
    first_finding = _finding(first_logon, "first")
    second_finding = _finding(second_logon, "second")

    selected = scenario._bs_p005_filter_findings(
        [first_finding, second_finding],
        component,
    )

    assert selected == [first_finding]


def test_non_reused_session_keeps_legacy_scenario_session_behavior():
    ts = datetime(2026, 9, 7, tzinfo=timezone.utc)
    logon = _event(event_id="4624", ts=ts)
    logoff = _event(event_id="4634", ts=ts + timedelta(minutes=5))
    chains = correlator._correlate_by_session([logon, logoff], [])
    session_chains = [chain for chain in chains if chain.chain_type == "session"]

    assert len(session_chains) == 1
    assert not getattr(session_chains[0], "session_instance_id", None)
    assert scenario._bs_p005_scope(session_chains[0])["sessions"] == {"0x12345"}
