#!/usr/bin/env python3
from pathlib import Path

# Temporary builder helper; never merged into the target branch.
ANALYZER = Path("breachscope/analyzer.py")
RULES = Path("rules/p2_10_event_rules.yml")
TEST = Path("tests/test_p2_10h_wmi_parent_correlation.py")

text = ANALYZER.read_text(encoding="utf-8")
old_import = "from .utils import get_event_key\n"
new_import = "from .utils import get_event_key, parse_timestamp\n"
assert text.count(old_import) == 1
text = text.replace(old_import, new_import, 1)

marker = "\ndef apply_rules(events: Iterable[Event], rules: List[Rule]) -> Iterator[Finding]:\n"
assert text.count(marker) == 1
helper = r'''

_WINDOWS_4688_PARENT_WINDOW_SECONDS = 300.0
_DERIVED_PARENT_CONTAINER = "_breachscope"
_DERIVED_PARENT_NAME = "resolved_security_4688_parent_process_name"
_DERIVED_PARENT_AGE = "resolved_security_4688_parent_age_seconds"


def _parse_windows_pid(value) -> Optional[int]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = int(text, 16) if text.casefold().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _security_4688_raw(event: Event) -> Optional[dict]:
    if str(event.source or "").casefold() != "microsoft-windows-security-auditing":
        return None
    if str(event.event_id or "") != "4688":
        return None
    raw = getattr(event, "raw", {}) or {}
    return raw if isinstance(raw, dict) else None


def _clear_derived_parent(raw: dict) -> None:
    derived = raw.get(_DERIVED_PARENT_CONTAINER)
    if not isinstance(derived, dict):
        return
    derived.pop(_DERIVED_PARENT_NAME, None)
    derived.pop(_DERIVED_PARENT_AGE, None)
    if not derived:
        raw.pop(_DERIVED_PARENT_CONTAINER, None)


def _iter_events_with_resolved_windows_4688_parents(
    events: Iterable[Event],
) -> Iterator[Event]:
    """Resolve recent Security 4688 parent process names from PID linkage.

    Windows Security 4688 exposes the new process ID as NewProcessId and the
    creator/parent process ID as ProcessId.  When an earlier 4688 on the same
    host created that parent PID, retain its NewProcessName as derived evidence
    for the child.  A five-minute forward-only window limits stale PID reuse.
    """
    recent: dict[Tuple[str, int], Tuple[object, str]] = {}

    for event in events:
        raw = _security_4688_raw(event)
        if raw is None:
            yield event
            continue

        _clear_derived_parent(raw)
        timestamp = parse_timestamp(str(event.timestamp or ""))
        host = str(event.host or "").casefold()
        parent_pid = _parse_windows_pid(raw.get("ProcessId"))
        new_pid = _parse_windows_pid(raw.get("NewProcessId"))
        new_process_name = str(raw.get("NewProcessName") or "").strip()

        if timestamp is not None and host and parent_pid is not None:
            parent = recent.get((host, parent_pid))
            if parent is not None:
                parent_timestamp, parent_process_name = parent
                age_seconds = (timestamp - parent_timestamp).total_seconds()
                if (
                    0.0 <= age_seconds <= _WINDOWS_4688_PARENT_WINDOW_SECONDS
                    and parent_process_name
                ):
                    derived = raw.setdefault(_DERIVED_PARENT_CONTAINER, {})
                    if isinstance(derived, dict):
                        derived[_DERIVED_PARENT_NAME] = parent_process_name
                        derived[_DERIVED_PARENT_AGE] = age_seconds

        if timestamp is not None and host and new_pid is not None and new_process_name:
            recent[(host, new_pid)] = (timestamp, new_process_name)

        yield event
'''
text = text.replace(marker, helper + marker, 1)

loop = "    for e in events:\n        texts: List[str] = []\n"
replacement = (
    "    for e in _iter_events_with_resolved_windows_4688_parents(events):\n"
    "        texts: List[str] = []\n"
)
assert text.count(loop) >= 1
text = text.replace(loop, replacement, 1)

chunks = "    chunks = [events[i:i + chunk_size] for i in range(0, len(events), chunk_size)]\n"
chunks_replacement = (
    "    enriched_events = list(_iter_events_with_resolved_windows_4688_parents(events))\n"
    "    chunks = [\n"
    "        enriched_events[i:i + chunk_size]\n"
    "        for i in range(0, len(enriched_events), chunk_size)\n"
    "    ]\n"
)
assert text.count(chunks) == 1
text = text.replace(chunks, chunks_replacement, 1)
ANALYZER.write_text(text, encoding="utf-8", newline="\n")

rules = RULES.read_text(encoding="utf-8")
assert "R-WMI-WMIPRVSE-CHILD-4688" not in rules
if not rules.endswith("\n"):
    rules += "\n"
rules += r'''

- id: R-WMI-WMIPRVSE-CHILD-4688
  name: WMI Provider Host Child Process
  description: Security 4688 child process whose recent same-host parent PID resolves to the Windows WMI provider host
  field: _breachscope.resolved_security_4688_parent_process_name
  operator: endswith
  pattern: '\wbem\WmiPrvSE.exe'
  severity: medium
  mitre_technique: T1047
  all_of:
    - field: event_id
      operator: equals
      pattern: "4688"
    - field: source
      operator: equals
      pattern: Microsoft-Windows-Security-Auditing
'''.lstrip("\n")
RULES.write_text(rules, encoding="utf-8", newline="\n")

TEST.write_text(r'''from pathlib import Path

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
''', encoding="utf-8", newline="\n")

print("P2-10H implementation patch applied")
