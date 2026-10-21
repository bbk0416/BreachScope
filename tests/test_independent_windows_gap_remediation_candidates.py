from __future__ import annotations

from pathlib import Path

import pytest

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_DIR = ROOT / "candidate_rules"

RULE_IDS = {
    "C-NETCFG-BUILTIN-DISCOVERY",
    "C-PERM-GROUPS-LOCAL-NET",
    "C-PERM-GROUPS-DOMAIN-NET",
    "C-SMB-ADMIN-SHARE-NET-USE",
    "C-REG-RUNKEY-HKLM-CMD",
    "C-WMI-REMOTE-PROCESS-CREATE",
}


def _rules():
    return load_rules(CANDIDATE_DIR)


def _event(
    image: str,
    command_line: str,
    *,
    source: str = "Microsoft-Windows-Sysmon",
    event_id: str = "1",
) -> Event:
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="LAB-01",
        source=source,
        event_id=event_id,
        user="LAB\\operator",
        command_line=command_line,
        raw={"Image": image, "event_data": {"Image": image, "CommandLine": command_line}},
    )


def _ids(image: str, command_line: str, **kwargs) -> set[str]:
    event = _event(image, command_line, **kwargs)
    return {finding.rule_id for finding in apply_rules([event], _rules())}


def test_candidate_pack_is_isolated_from_current_rulepack() -> None:
    candidates = _rules()
    current = load_rules(ROOT / "rules")

    assert {rule.id for rule in candidates} == RULE_IDS
    assert len(candidates) == 6
    assert len(current) == 69
    assert RULE_IDS.isdisjoint({rule.id for rule in current})


@pytest.mark.parametrize(
    ("image", "command"),
    [
        (r"C:\Windows\System32\ipconfig.exe", "ipconfig /all"),
        (r"C:\Windows\System32\nbtstat.exe", "nbtstat -n"),
        (r"C:\Windows\System32\route.exe", "route print"),
        (r"C:\Windows\System32\netsh.exe", "netsh interface ipv4 show addresses"),
    ],
)
def test_t1016_builtin_network_configuration_discovery_matches(image, command):
    assert _ids(image, command) == {"C-NETCFG-BUILTIN-DISCOVERY"}


@pytest.mark.parametrize(
    ("image", "command"),
    [
        (r"C:\Windows\System32\net.exe", "net localgroup"),
        (r"C:\Windows\System32\net.exe", "net localgroup administrators"),
        (r"C:\Windows\System32\net1.exe", 'net1.exe localgroup "Remote Desktop Users"'),
    ],
)
def test_t1069_local_group_query_matches(image, command):
    assert _ids(image, command) == {"C-PERM-GROUPS-LOCAL-NET"}


@pytest.mark.parametrize(
    ("image", "command"),
    [
        (r"C:\Windows\System32\net.exe", "net group /domain"),
        (r"C:\Windows\System32\net.exe", 'net group "Domain Admins" /domain'),
        (r"C:\Windows\System32\net1.exe", "net1.exe group Administrators /domain"),
    ],
)
def test_t1069_domain_group_query_matches(image, command):
    assert _ids(image, command) == {"C-PERM-GROUPS-DOMAIN-NET"}


@pytest.mark.parametrize(
    ("image", "command"),
    [
        (r"C:\Windows\System32\net.exe", r"net use \\server01\C$"),
        (
            r"C:\Windows\System32\net.exe",
            r"net.exe use Z: \\server01\ADMIN$ /user:CONTOSO\alice <credential>",
        ),
        (
            r"C:\Windows\System32\net1.exe",
            r"net1 use \\server01\IPC$ /user:CONTOSO\alice <credential>",
        ),
    ],
)
def test_t1021_002_admin_share_connection_matches(image, command):
    assert _ids(image, command) == {"C-SMB-ADMIN-SHARE-NET-USE"}


@pytest.mark.parametrize(
    "command",
    [
        r"reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d C:\ProgramData\updater.exe",
        r'reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Updater /d C:\ProgramData\updater.exe',
    ],
)
def test_t1547_001_hklm_run_key_add_matches(command):
    assert _ids(r"C:\Windows\System32\reg.exe", command) == {
        "C-REG-RUNKEY-HKLM-CMD"
    }


@pytest.mark.parametrize(
    "command",
    [
        r'wmic /node:"server01" /user:"CONTOSO\alice" /password:"<credential>" process call create "cmd.exe /c whoami"',
        r"wmic.exe /node:10.0.0.5 process call create calc.exe",
    ],
)
def test_t1047_remote_wmic_process_create_matches(command):
    assert _ids(r"C:\Windows\System32\wbem\wmic.exe", command) == {
        "C-WMI-REMOTE-PROCESS-CREATE"
    }


@pytest.mark.parametrize(
    ("image", "command"),
    [
        (r"C:\Windows\System32\ipconfig.exe", "ipconfig /flushdns"),
        (r"C:\Windows\System32\route.exe", "route add 10.0.0.0 mask 255.0.0.0 10.0.0.1"),
        (r"C:\Windows\System32\netsh.exe", "netsh advfirewall show allprofiles"),
        (r"C:\Windows\System32\net.exe", "net localgroup administrators alice /add"),
        (r"C:\Windows\System32\net.exe", 'net group "Domain Admins" alice /add /domain'),
        (r"C:\Windows\System32\net.exe", r"net use \\server01\C$ /delete"),
        (r"C:\Windows\System32\net.exe", r"net use \\server01\ordinary-share"),
        (
            r"C:\Windows\System32\reg.exe",
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d C:\x.exe",
        ),
        (
            r"C:\Windows\System32\reg.exe",
            r"reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (r"C:\Windows\System32\wbem\wmic.exe", "wmic process call create calc.exe"),
        (
            r"C:\Windows\System32\wbem\wmic.exe",
            "wmic /node:server01 computersystem get name",
        ),
    ],
)
def test_candidate_rules_reject_nearby_actions(image, command):
    assert _ids(image, command) == set()


def test_candidate_rules_require_expected_process_image() -> None:
    assert _ids(
        r"C:\Windows\System32\cmd.exe",
        "net localgroup administrators",
    ) == set()


def test_candidate_rules_require_sysmon_process_creation() -> None:
    assert _ids(
        r"C:\Windows\System32\net.exe",
        "net localgroup administrators",
        event_id="3",
    ) == set()
    assert _ids(
        r"C:\Windows\System32\net.exe",
        "net localgroup administrators",
        source="Microsoft-Windows-Security-Auditing",
    ) == set()


def test_t1105_is_intentionally_not_added_to_candidate_pack() -> None:
    assert all(
        str(rule.mitre_technique or "").upper() != "T1105"
        for rule in _rules()
    )
