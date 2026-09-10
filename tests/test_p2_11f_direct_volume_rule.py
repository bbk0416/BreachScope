from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


RULE_ID = "R-DIRECT-VOLUME-RAW-LOGICAL-DRIVE"


def _rule():
    by_id = {rule.id: rule for rule in load_rules(Path("rules"))}
    return by_id[RULE_ID]


def _event(
    *,
    image: str = r"C:\Windows\System32\cmd.exe",
    command_line: str,
    source: str = "Microsoft-Windows-Sysmon",
    event_id: str = "1",
) -> Event:
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="TESTHOST",
        source=source,
        event_id=event_id,
        user=r"TESTHOST\operator",
        command_line=command_line,
        raw={"Image": image},
    )


def _ids(event: Event) -> set[str]:
    return {finding.rule_id for finding in apply_rules([event], [_rule()])}


def test_atomic_observed_form_matches() -> None:
    cmd = (
        'powershell.exe & {$buffer = New-Object byte[] 11\n'
        '$handle = New-Object IO.FileStream "\\\\.\\C:", \'Open\', \'Read\', \'ReadWrite\'\n'
        '$handle.Read($buffer, 0, $buffer.Length)\n$handle.Close()}'
    )
    assert _ids(_event(command_line=cmd)) == {RULE_ID}


def test_process_name_is_not_required() -> None:
    cmd = r'tool.exe --device "\\.\D:" --mode inspect'
    assert _ids(_event(image=r"C:\Temp\tool.exe", command_line=cmd)) == {RULE_ID}


def test_drive_letter_case_variation_matches() -> None:
    assert _ids(_event(command_line=r'tool.exe "\\.\e:"')) == {RULE_ID}


def test_named_pipe_is_excluded() -> None:
    cmd = r'firefox.exe "\\.\pipe\gecko-crash-server-pipe.7528"'
    assert _ids(_event(command_line=cmd)) == set()


def test_normal_drive_path_is_excluded() -> None:
    assert _ids(_event(command_line=r'tool.exe C:\Windows\win.ini')) == set()


def test_device_prefix_without_drive_letter_is_excluded() -> None:
    assert _ids(_event(command_line=r'tool.exe "\\.\PhysicalDrive0"')) == set()


def test_wrong_provider_is_excluded() -> None:
    assert _ids(
        _event(
            command_line=r'tool.exe "\\.\C:"',
            source="Microsoft-Windows-Security-Auditing",
        )
    ) == set()


def test_wrong_event_id_is_excluded() -> None:
    assert _ids(_event(command_line=r'tool.exe "\\.\C:"', event_id="13")) == set()


def test_rule_metadata_and_non_atomic_semantics() -> None:
    rule = _rule()
    assert rule.mitre_technique == "T1006"
    assert rule.severity == "medium"
    text = " ".join([rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)])
    lowered = text.lower()
    assert "powershell" not in lowered
    assert "pwsh" not in lowered
    assert "filestream" not in lowered
    assert "admin_test" not in text
    assert "SERVER002" not in text
