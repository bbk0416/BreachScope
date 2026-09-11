from __future__ import annotations

from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


RULE_ID = "R-NETWORK-PROVIDER-CREDENTIAL-CAPTURE-SETUP"


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


def _combined_command() -> str:
    return (
        r"powershell.exe Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order "
        r"-Name ProviderOrder -Value 'LanmanWorkstation,ExampleProvider'; "
        r"Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ExampleProvider\NetworkProvider "
        r"-Name ProviderPath -Value 'C:\ProgramData\Example\provider.dll'"
    )


def test_combined_network_provider_setup_matches() -> None:
    assert _ids(_event(command_line=_combined_command())) == {RULE_ID}


def test_provider_name_is_not_hard_coded() -> None:
    cmd = _combined_command().replace("ExampleProvider", "ContosoCredentialProvider")
    assert _ids(_event(command_line=cmd)) == {RULE_ID}


def test_order_change_alone_is_excluded() -> None:
    cmd = (
        r"powershell.exe Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order "
        r"-Name ProviderOrder -Value 'LanmanWorkstation,ExampleProvider'"
    )
    assert _ids(_event(command_line=cmd)) == set()


def test_provider_path_registration_alone_is_excluded() -> None:
    cmd = (
        r"powershell.exe Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ExampleProvider\NetworkProvider "
        r"-Name ProviderPath -Value 'C:\ProgramData\Example\provider.dll'"
    )
    assert _ids(_event(command_line=cmd)) == set()


def test_generic_networkprovider_mention_is_excluded() -> None:
    assert _ids(_event(command_line=r"cmd.exe /c echo NetworkProvider")) == set()


def test_wrong_source_is_excluded() -> None:
    assert _ids(
        _event(
            command_line=_combined_command(),
            source="Microsoft-Windows-Security-Auditing",
        )
    ) == set()


def test_wrong_event_id_is_excluded() -> None:
    assert _ids(_event(command_line=_combined_command(), event_id="13")) == set()


def test_rule_metadata_and_non_atomic_semantics() -> None:
    rule = _rule()
    assert rule.mitre_technique == "T1003"
    assert rule.severity == "low"
    text = " ".join([rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)])
    lowered = text.lower()
    assert "nppspy" not in lowered
    assert "exampleprovider" not in lowered
    assert "powershell" not in lowered
