from pathlib import Path

from breachscope.analyzer import apply_rules
from breachscope.rules import load_rules
from breachscope.schemas import Event


ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "rules")


def _event(command_line: str, *, source: str = "Microsoft-Windows-Sysmon", event_id: str = "1") -> Event:
    return Event(
        timestamp="2026-09-26T00:00:00Z",
        host="fixture-host",
        source=source,
        event_id=event_id,
        command_line=command_line,
        raw={},
    )


def _rule_ids(command_line: str, **kwargs) -> set[str]:
    return {
        finding.rule_id
        for finding in apply_rules([_event(command_line, **kwargs)], RULES)
    }


def _techniques(command_line: str, **kwargs) -> set[str]:
    return {
        finding.mitre_technique
        for finding in apply_rules([_event(command_line, **kwargs)], RULES)
        if finding.mitre_technique
    }


def test_rulepack_adds_four_independent_command_coverage_rules():
    ids = {rule.id for rule in RULES}

    assert len(RULES) == 73
    assert {
        "R-NETWORK-CONFIG-NBTSTAT",
        "R-PERMISSION-GROUPS-LOCAL-NET",
        "R-PERMISSION-GROUPS-DOMAIN-NET",
        "R-SMB-ADMIN-SHARE-NET-USE",
    } <= ids


def test_t1016_nbtstat_discovery_accepts_atomic_and_documented_switches():
    assert "R-NETWORK-CONFIG-NBTSTAT" in _rule_ids("nbtstat -n")
    assert "R-NETWORK-CONFIG-NBTSTAT" in _rule_ids("NBTSTAT.EXE /n")
    assert "T1016" in _techniques("nbtstat -n")


def test_t1016_does_not_treat_nbtstat_cache_purge_as_discovery():
    assert "R-NETWORK-CONFIG-NBTSTAT" not in _rule_ids("nbtstat /R")
    assert "R-NETWORK-CONFIG-NBTSTAT" not in _rule_ids("nbtstat /RR")


def test_t1016_requires_sysmon_process_creation_context():
    assert "R-NETWORK-CONFIG-NBTSTAT" not in _rule_ids(
        "nbtstat -n",
        source="Microsoft-Windows-Security-Auditing",
        event_id="4688",
    )


def test_t1069_local_group_discovery_and_modification_exclusion():
    ids = _rule_ids('net localgroup "Administrators"')
    assert "R-PERMISSION-GROUPS-LOCAL-NET" in ids
    assert "T1069.001" in _techniques('net localgroup "Administrators"')

    assert "R-PERMISSION-GROUPS-LOCAL-NET" not in _rule_ids(
        'net localgroup "Administrators" fixture-user /add'
    )
    assert "R-PERMISSION-GROUPS-LOCAL-NET" not in _rule_ids(
        'net localgroup "Administrators" fixture-user /delete'
    )


def test_t1069_domain_group_discovery_and_modification_exclusion():
    ids = _rule_ids('net group "Domain Admins" /domain')
    assert "R-PERMISSION-GROUPS-DOMAIN-NET" in ids
    assert "T1069.002" in _techniques('net group "Domain Admins" /domain')

    assert "R-PERMISSION-GROUPS-DOMAIN-NET" in _rule_ids("net1.exe group /dom")
    assert "R-PERMISSION-GROUPS-DOMAIN-NET" not in _rule_ids(
        'net group "Domain Admins" fixture-user /add /domain'
    )


def test_t1021_002_net_use_admin_share_is_specific():
    ids = _rule_ids(r"net use \\server01\C$ * /user:CORP\fixture-user")
    assert "R-SMB-ADMIN-SHARE-NET-USE" in ids
    assert "T1021.002" in _techniques(
        r"net use \\server01\ADMIN$ * /user:CORP\fixture-user"
    )

    assert "R-SMB-ADMIN-SHARE-NET-USE" not in _rule_ids(
        r"net use \\server01\Public"
    )


def test_t1547_001_run_key_covers_hkcu_and_hklm_without_runservices():
    for command in (
        r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "C:\Program Files\Updater\updater.exe"',
        r'reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "C:\Program Files\Updater\updater.exe"',
        r'reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce /v Updater /d "C:\Updater.exe"',
    ):
        assert "R-REG-RunKey" in _rule_ids(command)
        assert "T1547.001" in _techniques(command)

    assert "R-REG-RunKey" not in _rule_ids(
        r"reg add HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices /v X /d C:\x.exe"
    )


def test_t1047_wmic_process_create_allows_remote_connection_options():
    local = 'wmic process call create "cmd.exe /c whoami"'
    remote = (
        'wmic /node:"server01" /user:"CORP\\fixture-user" '
        '/password:"fixture-password" process call create "cmd.exe /c whoami"'
    )

    assert "R-WMI-Create" in _rule_ids(local)
    assert "R-WMI-Create" in _rule_ids(remote)
    assert "T1047" in _techniques(remote)

    assert "R-WMI-Create" not in _rule_ids("wmic process get name")


def test_smb_copy_is_not_posthoc_relabelled_as_t1105():
    techniques = _techniques(
        r'cmd /c copy "C:\Tools\tool.exe" "\\server01\C$\tool.exe"'
    )

    assert "T1105" not in techniques
