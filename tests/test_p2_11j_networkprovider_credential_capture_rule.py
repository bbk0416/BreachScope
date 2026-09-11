from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


RULE_ID = "R-NETWORKPROVIDER-CREDENTIAL-CAPTURE-CONFIG"


def _rule():
    by_id = {rule.id: rule for rule in load_rules(Path("rules"))}
    return by_id[RULE_ID]


def _event(
    *,
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
        raw={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
    )


def _ids(event: Event) -> set[str]:
    return {finding.rule_id for finding in apply_rules([event], [_rule()])}


def _generic_capture_command() -> str:
    return (
        r"$p=Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order -Name PROVIDERORDER; "
        r"Set-ItemProperty -Path $p.PSPath -Name PROVIDERORDER -Value ($p.PROVIDERORDER + ',ExampleProvider'); "
        r"New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ExampleProvider\NetworkProvider; "
        r"New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ExampleProvider\NetworkProvider "
        r"-Name ProviderPath -Value '%SystemRoot%\System32\ExampleProvider.dll'"
    )


def test_generic_networkprovider_order_and_providerpath_matches() -> None:
    assert _ids(_event(command_line=_generic_capture_command())) == {RULE_ID}


def test_multiline_generic_form_matches() -> None:
    cmd = (
        "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order -Name PROVIDERORDER\n"
        "Set-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order -Name PROVIDERORDER -Value ExampleProvider\n"
        "New-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\ExampleProvider\\NetworkProvider -Name ProviderPath -Value C:\\Example.dll"
    )
    assert _ids(_event(command_line=cmd)) == {RULE_ID}


def test_provider_order_only_is_excluded() -> None:
    cmd = r"Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order -Name PROVIDERORDER -Value LanmanWorkstation"
    assert _ids(_event(command_line=cmd)) == set()


def test_provider_path_only_is_excluded() -> None:
    cmd = r"New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\ExampleProvider\NetworkProvider -Name ProviderPath -Value C:\Example.dll"
    assert _ids(_event(command_line=cmd)) == set()


def test_unrelated_service_providerpath_is_excluded() -> None:
    cmd = (
        r"Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order -Name PROVIDERORDER -Value ExampleProvider; "
        r"New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\ExampleProvider -Name ProviderPath -Value C:\Example.dll"
    )
    assert _ids(_event(command_line=cmd)) == set()


def test_wrong_provider_is_excluded() -> None:
    assert _ids(_event(command_line=_generic_capture_command(), source="Microsoft-Windows-Security-Auditing")) == set()


def test_wrong_event_id_is_excluded() -> None:
    assert _ids(_event(command_line=_generic_capture_command(), event_id="13")) == set()


def test_rule_metadata_is_low_confidence_and_tool_independent() -> None:
    rule = _rule()
    assert rule.mitre_technique == "T1003"
    assert rule.severity == "low"
    text = " ".join([rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)]).lower()
    assert "nppspy" not in text
    assert "atomic" not in text
    assert "admin_test" not in text
    assert "exampleprovider" not in text
    assert "credential" in text
