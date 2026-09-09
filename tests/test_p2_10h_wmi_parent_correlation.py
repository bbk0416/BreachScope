from pathlib import Path

from breachscope.analyzer import apply_rules, apply_rules_parallel
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
RULE_ID = "R-WMI-WMIPRVSE-CHILD-4688"


def _rules():
    return load_rules(ROOT / "rules")


def _event(
    timestamp: str,
    *,
    host: str = "host.example.test",
    new_pid: str,
    parent_pid: str,
    image: str,
    source: str = "Microsoft-Windows-Security-Auditing",
    event_id: str = "4688",
) -> Event:
    return Event(
        timestamp=timestamp,
        host=host,
        source=source,
        event_id=event_id,
        command_line="",
        raw={
            "NewProcessId": new_pid,
            "ProcessId": parent_pid,
            "NewProcessName": image,
        },
    )


def _parent(ts: str = "2026-09-10T00:00:00+00:00", host: str = "host.example.test") -> Event:
    return _event(
        ts,
        host=host,
        new_pid="0x0ae8",
        parent_pid="0x0248",
        image=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
    )


def _child(
    ts: str = "2026-09-10T00:00:00.031000+00:00",
    host: str = "host.example.test",
    image: str = r"C:\Windows\System32\notepad.exe",
) -> Event:
    return _event(
        ts,
        host=host,
        new_pid="0x0424",
        parent_pid="0x0ae8",
        image=image,
    )


def _matches(events):
    return [f for f in apply_rules(events, _rules()) if f.rule_id == RULE_ID]


def test_wmiprvse_child_matches_t1047_without_child_name_dependency() -> None:
    child = _child(image=r"C:\Windows\System32\rundll32.exe")
    matches = _matches([_parent(), child])
    assert len(matches) == 1
    assert matches[0].event is child
    assert matches[0].mitre_technique == "T1047"


def test_wmiprvse_start_event_itself_does_not_match() -> None:
    assert not _matches([_parent()])


def test_non_wbem_process_named_wmiprvse_does_not_match() -> None:
    parent = _event(
        "2026-09-10T00:00:00+00:00",
        new_pid="0x0ae8",
        parent_pid="0x0248",
        image=r"C:\Temp\WmiPrvSE.exe",
    )
    assert not _matches([parent, _child()])


def test_parent_relation_expires_after_five_minutes() -> None:
    assert not _matches([_parent(), _child("2026-09-10T00:05:00.001000+00:00")])


def test_parent_must_be_on_same_host() -> None:
    assert not _matches([_parent(host="host-a"), _child(host="host-b")])


def test_parent_must_precede_child() -> None:
    assert not _matches([_child(), _parent()])


def test_wrong_event_provider_does_not_match() -> None:
    child = _event(
        "2026-09-10T00:00:00.031000+00:00",
        new_pid="0x0424",
        parent_pid="0x0ae8",
        image=r"C:\Windows\System32\notepad.exe",
        source="Other-Provider",
    )
    assert not _matches([_parent(), child])


def test_parallel_analysis_resolves_parent_before_chunk_split() -> None:
    child = _child()
    findings = apply_rules_parallel(
        [_parent(), child],
        _rules(),
        max_workers=2,
        chunk_size=1,
    )
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert len(matches) == 1
    assert matches[0].event is child
