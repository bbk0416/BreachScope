from pathlib import Path

import pytest

from breachscope.analyzer import apply_rules
from breachscope.ingest import iter_event_xml_records
from breachscope.rules import load_rules
from breachscope.schemas import Event

ROOT = Path(__file__).resolve().parents[1]
RULE_IDS = {"R-WINRS-REMOTE-TARGET", "R-DOMAIN-ACCOUNT-DISCOVERY-CMD"}


def _rules():
    return [rule for rule in load_rules(ROOT / "rules") if rule.id in RULE_IDS]


def _event(command_line, *, source="Microsoft-Windows-Sysmon", event_id="1"):
    return Event(
        timestamp="2026-01-01T00:00:00Z",
        host="LAB-01",
        source=source,
        event_id=event_id,
        level="",
        user="LAB\\user",
        command_line=command_line,
        raw={"event_data": {"CommandLine": command_line}},
    )


def _rule_ids(command_line, **kwargs):
    return {f.rule_id for f in apply_rules([_event(command_line, **kwargs)], _rules())}


@pytest.mark.parametrize(
    "command",
    [
        'winrs  -r:win-host-987.attackrange.local "ipconfig"',
        "winrs.exe -r:server01.contoso.local whoami",
    ],
)
def test_winrs_remote_target_matches(command):
    assert "R-WINRS-REMOTE-TARGET" in _rule_ids(command)


@pytest.mark.parametrize(
    "command",
    [
        "net users /domain",
        r"C:\Windows\system32\net1 user /domain",
        "dsquery user",
        "powershell.exe Get-ADUser -Filter *",
        "powershell.exe Get-DomainUser",
        r"wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname /VALUE",
        r"powershell get-wmiobject -class ds_user -namespace root\directory\ldap",
    ],
)
def test_domain_account_discovery_matches(command):
    assert "R-DOMAIN-ACCOUNT-DISCOVERY-CMD" in _rule_ids(command)


@pytest.mark.parametrize(
    "command",
    [
        "winrs -?",
        "net user alice",
        "net localgroup administrators",
        "powershell.exe Get-ADComputer -Filter *",
        "dsquery computer",
    ],
)
def test_candidate_rules_reject_nearby_benign_or_other_discovery(command):
    assert not _rule_ids(command)


def test_candidate_rules_require_sysmon_process_creation():
    assert not _rule_ids("net users /domain", event_id="3")
    assert not _rule_ids(
        "net users /domain",
        source="Microsoft-Windows-Security-Auditing",
    )


def test_multiline_event_framing_uses_event_boundaries(tmp_path):
    first = (
        "<Event><System><EventID>1</EventID></System><EventData>"
        "<Data Name='CommandLine'>powershell\nsecond line</Data>"
        "</EventData></Event>"
    )
    second = "<Event><System><EventID>3</EventID></System></Event>"
    path = tmp_path / "events.log"
    path.write_text(first + "\n" + second + "\n", encoding="utf-8")
    records = list(iter_event_xml_records(path))
    assert records == [first, second]


def test_multiline_event_framing_fails_closed_on_unterminated_record(tmp_path):
    path = tmp_path / "broken.log"
    path.write_text("<Event><System>unfinished", encoding="utf-8")
    with pytest.raises(ValueError, match="unterminated"):
        list(iter_event_xml_records(path))
