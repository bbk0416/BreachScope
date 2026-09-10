from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


RULE_ID = "R-DIRECT-VOLUME-POWERSHELL-FILESTREAM-READ"


def _rule():
    by_id = {rule.id: rule for rule in load_rules(Path("rules"))}
    return by_id[RULE_ID]


def _event(
    *,
    image: str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
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


def test_atomic_semantic_form_matches() -> None:
    cmd = (
        'powershell.exe & {$buffer = New-Object byte[] 11\n'
        '$handle = New-Object IO.FileStream "\\\\.\\C:", \'Open\', \'Read\', \'ReadWrite\'\n'
        '$handle.Read($buffer, 0, $buffer.Length)\n$handle.Close()}'
    )
    assert _ids(_event(command_line=cmd)) == {RULE_ID}


def test_pwsh_and_different_drive_match() -> None:
    cmd = r'pwsh.exe -c $h = New-Object System.IO.FileStream "\\.\D:", "Open", "Read"; $h.Read($b,0,1)'
    assert _ids(
        _event(image=r"C:\Program Files\PowerShell\7\pwsh.exe", command_line=cmd)
    ) == {RULE_ID}


def test_case_variation_matches() -> None:
    cmd = r'POWERSHELL -c New-Object io.filestream "\\.\E:", "OPEN", "READ"'
    assert _ids(_event(command_line=cmd)) == {RULE_ID}


def test_normal_file_filestream_is_excluded() -> None:
    cmd = r'powershell.exe -c New-Object IO.FileStream "C:\temp\x.bin", "Open", "Read"'
    assert _ids(_event(command_line=cmd)) == set()


def test_raw_volume_without_filestream_is_excluded() -> None:
    cmd = r'powershell.exe -c Write-Output "\\.\C:"; Read-Host Open'
    assert _ids(_event(command_line=cmd)) == set()


def test_raw_volume_filestream_without_open_is_excluded() -> None:
    cmd = r'powershell.exe -c New-Object IO.FileStream "\\.\C:", "Create", "Read"'
    assert _ids(_event(command_line=cmd)) == set()


def test_raw_volume_filestream_without_read_is_excluded() -> None:
    cmd = r'powershell.exe -c New-Object IO.FileStream "\\.\C:", "Open", "Write"'
    assert _ids(_event(command_line=cmd)) == set()


def test_wrong_process_is_excluded() -> None:
    cmd = r'cmd.exe /c echo IO.FileStream "\\.\C:" Open Read'
    assert _ids(_event(image=r"C:\Windows\System32\cmd.exe", command_line=cmd)) == set()


def test_wrong_provider_is_excluded() -> None:
    cmd = r'powershell.exe -c New-Object IO.FileStream "\\.\C:", "Open", "Read"'
    assert _ids(_event(command_line=cmd, source="Microsoft-Windows-Security-Auditing")) == set()


def test_wrong_event_id_is_excluded() -> None:
    cmd = r'powershell.exe -c New-Object IO.FileStream "\\.\C:", "Open", "Read"'
    assert _ids(_event(command_line=cmd, event_id="13")) == set()


def test_rule_metadata_and_claim_semantics() -> None:
    rule = _rule()
    assert rule.mitre_technique == "T1006"
    assert rule.severity == "medium"
    text = " ".join([rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)])
    assert "admin_test" not in text
    assert "SERVER002" not in text
    assert "11" not in text
