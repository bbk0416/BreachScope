from breachscope.analyzer import apply_rules, apply_rules_parallel
from breachscope.schemas import Event, Rule

def event(raw=None):
    e=Event(
        timestamp="2026-01-01T00:00:00Z",
        host="WS",
        source="Microsoft-Windows-Eventlog",
        event_id="104",
        command_line="",
    )
    e.raw=raw or {}
    return e

def rule():
    return Rule(
        id="R",name="r",description="t",
        field="event_id",operator="equals",pattern="104",
        severity="high",
        all_of=[{"field":"source","operator":"equals","pattern":"Microsoft-Windows-Eventlog"}],
    )

def test_distinct_nested_record_ids_survive():
    a=event({"raw":{"system":{"Channel":"System","EventRecordID":"1"}}})
    b=event({"raw":{"system":{"Channel":"System","EventRecordID":"2"}}})
    assert len(list(apply_rules([a,b],[rule()])))==2

def test_same_record_id_different_channel_survives():
    a=event({"raw":{"system":{"Channel":"System","EventRecordID":"1"}}})
    b=event({"raw":{"system":{"Channel":"Security","EventRecordID":"1"}}})
    assert len(list(apply_rules([a,b],[rule()])))==2

def test_exact_windows_duplicate_still_dedupes():
    raw={"raw":{"system":{"Channel":"System","EventRecordID":"1"}}}
    assert len(list(apply_rules([event(raw),event(raw)],[rule()])))==1

def test_parallel_distinct_nested_record_ids_survive():
    a=event({"payload":{"raw":{"system":{"Channel":"System","EventRecordID":"1"}}}})
    b=event({"payload":{"raw":{"system":{"Channel":"System","EventRecordID":"2"}}}})
    assert len(apply_rules_parallel([a,b],[rule()],max_workers=1,chunk_size=10))==2

def test_generic_without_windows_identity_keeps_historical_dedupe():
    r=Rule(
        id="G",name="g",description="t",
        field="source",operator="equals",pattern="Microsoft-Windows-Eventlog",
        severity="medium",
    )
    assert len(list(apply_rules([event(),event()],[r])))==1
