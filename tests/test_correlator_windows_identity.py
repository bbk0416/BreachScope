from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from breachscope.correlator import CorrelationRule, correlate_events
from breachscope.schemas import Event, Finding
from breachscope.utils import get_event_identity_key


def _event(*, ts, source, record_id, channel="System"):
    return Event(
        timestamp=ts.isoformat(),
        host="WIN-A",
        source=source,
        event_id="1",
        user="alice",
        command_line="",
        raw={"raw": {"system": {"Channel": channel, "EventRecordID": str(record_id)}}},
    )


def _record_id(event):
    return event.raw["raw"]["system"]["EventRecordID"]


def test_windows_record_identity_keeps_same_coarse_key_events_distinct():
    ts = datetime(2026, 9, 4, tzinfo=timezone.utc)
    first = _event(ts=ts, source="Anchor", record_id=1)
    second = _event(ts=ts, source="Anchor", record_id=2)

    assert first.timestamp == second.timestamp
    assert first.host == second.host
    assert first.source == second.source
    assert first.event_id == second.event_id
    assert get_event_identity_key(first) != get_event_identity_key(second)


def test_finding_attaches_only_to_matching_windows_record_and_chains_do_not_collapse():
    ts = datetime(2026, 9, 4, tzinfo=timezone.utc)
    first = _event(ts=ts, source="Anchor", record_id=1)
    second = _event(ts=ts, source="Anchor", record_id=2)
    follow = _event(ts=ts + timedelta(seconds=10), source="Follow", record_id=3)

    finding = Finding(
        rule_id="R1",
        rule_name="record-one",
        severity="high",
        mitre_technique="T0001",
        event=first,
        matched_value="x",
    )
    rule = CorrelationRule(
        rule_id="corr",
        name="corr",
        description="identity regression",
        event_a_patterns=["source:Anchor"],
        event_b_patterns=["source:Follow"],
        time_window_seconds=60,
        required_fields=["host"],
        chain_type="identity",
    )

    chains = correlate_events([first, second, follow], [finding], [rule])
    identity_chains = [c for c in chains if c.chain_type == "identity"]

    assert len(identity_chains) == 2
    by_record = {_record_id(c.events[0]): c for c in identity_chains}
    assert [f.rule_id for f in by_record["1"].findings] == ["R1"]
    assert by_record["2"].findings == []


def test_confidence_time_span_uses_actual_last_matched_event():
    ts = datetime(2026, 9, 4, tzinfo=timezone.utc)
    anchor = _event(ts=ts, source="Anchor", record_id=10)
    matched = _event(ts=ts + timedelta(seconds=10), source="Follow", record_id=11)
    scanned_but_unmatched = _event(ts=ts + timedelta(seconds=500), source="Other", record_id=12)

    rule = CorrelationRule(
        rule_id="corr",
        name="corr",
        description="time-span regression",
        event_a_patterns=["source:Anchor"],
        event_b_patterns=["source:Follow"],
        time_window_seconds=600,
        required_fields=["host"],
        chain_type="time_span",
    )

    chains = correlate_events([anchor, matched, scanned_but_unmatched], [], [rule])
    chain = next(c for c in chains if c.chain_type == "time_span")

    assert chain.end_time == ts + timedelta(seconds=10)
    assert chain.confidence == pytest.approx(0.5)
