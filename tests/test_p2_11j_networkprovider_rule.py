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
    image: str = r"C:\Windows\System32\cmd.exe",
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


def _generic_setup() -> str:
    return (
        r"tool.exe --script HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order "
        r"ProviderOrder LanmanWorkstation,CredCapture "
        r"HKLM:\SYSTEM\CurrentControlSet\Services\CredCapture\NetworkProvider "
        r"ProviderPath %SystemRoot%\System32\capture.dll"
    )


def test_generic_networkprovider_setup_matches() -> None:
    assert _ids(_event(command_line=_generic_setup())) == {RULE_ID}


def test_process_name_is_not_required() -> None:
    assert _ids(_event(command_line=_generic_setup(), image=r"C:\Temp\helper.exe")) == {RULE_ID}


def test_order_only_is_excluded() -> None:
    cmd = r"tool.exe HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order ProviderOrder"
    assert _ids(_event(command_line=cmd)) == set()


def test_service_registration_only_is_excluded() -> None:
    cmd = (
        r"tool.exe HKLM:\SYSTEM\CurrentControlSet\Services\CredCapture\NetworkProvider "
        r"ProviderPath %SystemRoot%\System32\capture.dll"
    )
    assert _ids(_event(command_line=cmd)) == set()


def test_missing_providerorder_is_excluded() -> None:
    cmd = (
        r"tool.exe HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order "
        r"HKLM:\SYSTEM\CurrentControlSet\Services\CredCapture\NetworkProvider "
        r"ProviderPath %SystemRoot%\System32\capture.dll"
    )
    assert _ids(_event(command_line=cmd)) == set()


def test_missing_providerpath_is_excluded() -> None:
    cmd = (
        r"tool.exe HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order ProviderOrder "
        r"HKLM:\SYSTEM\CurrentControlSet\Services\CredCapture\NetworkProvider"
    )
    assert _ids(_event(command_line=cmd)) == set()


def test_wrong_provider_is_excluded() -> None:
    assert _ids(_event(command_line=_generic_setup(), source="Microsoft-Windows-Security-Auditing")) == set()


def test_wrong_event_id_is_excluded() -> None:
    assert _ids(_event(command_line=_generic_setup(), event_id="13")) == set()


def test_rule_metadata_is_generic_and_not_atomic_specific() -> None:
    rule = _rule()
    assert rule.mitre_technique == "T1003"
    assert rule.severity == "medium"
    text = " ".join([rule.id, rule.name, rule.description, rule.pattern, str(rule.all_of)])
    lowered = text.lower()
    assert "nppspy" not in lowered
    assert "atomic" not in lowered
    assert "powershell" not in lowered
    assert "admin_test" not in lowered
    assert "server002" not in lowered
