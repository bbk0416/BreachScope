from __future__ import annotations

from datetime import datetime, timezone

from breachscope.correlator import EventChain
from breachscope.scenario import infer_scenarios
from breachscope.schemas import Event, Finding


def _event(host: str, session: str, record_id: str) -> Event:
    return Event(
        timestamp="2026-09-04T00:00:00+00:00",
        host=host,
        source="Microsoft-Windows-PowerShell",
        event_id="4104",
        command_line="powershell -enc AAAA",
        raw={
            "system": {
                "Channel": "Microsoft-Windows-PowerShell/Operational",
                "EventRecordID": record_id,
            },
            "canonical": {
                "host": {"name": host},
                "session": {"id": session},
            },
        },
    )


def _chain(host: str, session: str, record_id: str) -> EventChain:
    ev = _event(host, session, record_id)
    now = datetime(2026, 9, 4, tzinfo=timezone.utc)
    return EventChain(
        chain_id=f"chain-{host}-{session}",
        events=[ev],
        findings=[],
        start_time=now,
        end_time=now,
        description="encoded command",
        confidence=0.8,
        chain_type="encoded_exec",
    )


def _finding(ch: EventChain) -> Finding:
    return Finding(
        rule_id="R-ENC",
        rule_name="Encoded PowerShell",
        severity="high",
        mitre_technique="T1059.001",
        event=ch.events[0],
        matched_value="-enc",
    )


def _two_components():
    a = _chain("HOST-A", "0x1", "101")
    b = _chain("HOST-B", "0x2", "202")
    return [a, b], [_finding(a), _finding(b)]


def test_scenario_ids_are_unique_across_independent_components():
    chains, findings = _two_components()
    scenarios = infer_scenarios(chains, findings)
    ids = [item.scenario_id for item in scenarios]
    assert len(ids) >= 4
    assert len(ids) == len(set(ids))


def test_scenario_ids_are_deterministic_for_same_evidence():
    chains, findings = _two_components()
    first = [item.scenario_id for item in infer_scenarios(chains, findings)]
    second = [item.scenario_id for item in infer_scenarios(chains, findings)]
    assert first == second


def test_scenario_ids_follow_evidence_not_component_order():
    chains, findings = _two_components()
    forward = {item.scenario_id for item in infer_scenarios(chains, findings)}
    reverse = {item.scenario_id for item in infer_scenarios(list(reversed(chains)), findings)}
    assert forward == reverse


def test_scenario_ids_keep_legacy_semantic_suffix():
    chains, findings = _two_components()
    ids = [item.scenario_id for item in infer_scenarios(chains, findings)]
    assert any(item.endswith("encoded_cred_dump") for item in ids)
    assert any("scenario_chain_encoded_" in item for item in ids)
