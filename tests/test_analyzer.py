"""규칙 매칭 로직 테스트"""

from breachscope.analyzer import apply_rules
from breachscope.schemas import Event, Rule


def _event(command_line: str) -> Event:
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="WS-01",
        source="ProcessCreate",
        event_id="4688",
        command_line=command_line,
    )


def test_contains_operator_uses_full_pattern_body():
    """operator=contains일 때 pattern을 잘못 잘라 짧은 글자에 오탐하면 안 된다."""
    rule = Rule(
        id="R-MSHTA-Remote",
        name="MSHTA Remote Load",
        description="mshta remote load",
        field="command_line",
        operator="contains",
        pattern="mshta http",
        severity="medium",
        mitre_technique="T1218.005",
    )

    false_positive_event = _event("powershell.exe -encodedcommand AAAABBBBCCCCDDDD")
    assert list(apply_rules([false_positive_event], [rule])) == []

    real_event = _event("mshta http://example.local/a.hta")
    findings = list(apply_rules([real_event], [rule]))
    assert len(findings) == 1
    assert findings[0].matched_value.lower() == "mshta http"


def test_contains_operator_supports_pipe_separated_targets():
    rule = Rule(
        id="R-ENC",
        name="Encoded PowerShell Command",
        description="encoded powershell",
        field="command_line",
        operator="contains",
        pattern="-encodedcommand|-enc",
        severity="medium",
        mitre_technique="T1059.001",
    )
    findings = list(apply_rules([_event("powershell.exe -encodedcommand AAAA")], [rule]))
    assert len(findings) == 1
    assert findings[0].matched_value.lower() == "-encodedcommand"


def test_prefix_notation_still_works():
    rule = Rule(
        id="R-PREFIX",
        name="Prefix Contains",
        description="prefix notation",
        field="command_line",
        pattern="contains:curl",
        severity="medium",
    )
    findings = list(apply_rules([_event("powershell curl http://example.local")], [rule]))
    assert len(findings) == 1
    assert findings[0].matched_value.lower() == "curl"
