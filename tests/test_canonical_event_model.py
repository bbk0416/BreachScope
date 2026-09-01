from __future__ import annotations

from breachscope.canonical import build_canonical_event
from breachscope.ingest import _extract_from_xml


def test_security_4688_and_sysmon_1_share_process_start_taxonomy():
    security = {
        "event_id": 4688,
        "source": "Microsoft-Windows-Security-Auditing",
        "host": "WIN-A",
        "raw": {
            "event_data": {
                "NewProcessId": "0x1234",
                "ProcessId": "0x1000",
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentProcessName": r"C:\Windows\explorer.exe",
                "CommandLine": "powershell.exe -NoProfile",
                "SubjectUserName": "alice",
                "SubjectUserSid": "S-1-5-21-1",
                "SubjectLogonId": "0x777",
            }
        },
    }
    sysmon = {
        "event_id": 1,
        "source": "Microsoft-Windows-Sysmon",
        "host": "WIN-B",
        "raw": {
            "event_data": {
                "ProcessId": "4660",
                "ParentProcessId": "4096",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentImage": r"C:\Windows\explorer.exe",
                "CommandLine": "powershell.exe -NoProfile",
                "User": r"CORP\alice",
                "ProcessGuid": "{P}",
                "ParentProcessGuid": "{PP}",
            }
        },
    }

    sec = build_canonical_event(security)
    sys = build_canonical_event(sysmon)

    assert sec["event"]["category"] == sys["event"]["category"] == "process"
    assert sec["event"]["action"] == sys["event"]["action"] == "process_start"
    assert sec["process"]["pid"] == sys["process"]["pid"] == 4660
    assert sec["process"]["parent_pid"] == sys["process"]["parent_pid"] == 4096
    assert sec["process"]["executable"].endswith("powershell.exe")
    assert sys["process"]["executable"].endswith("powershell.exe")
    assert sec["session"]["id"] == "0x777"


def test_sysmon_3_maps_network_connection_fields():
    event = {
        "event_id": 3,
        "source": "Microsoft-Windows-Sysmon",
        "host": "WIN-A",
        "raw": {
            "event_data": {
                "ProcessId": "123",
                "Image": r"C:\Windows\System32\curl.exe",
                "SourceIp": "10.0.0.10",
                "SourcePort": "51515",
                "DestinationIp": "203.0.113.8",
                "DestinationPort": "443",
                "DestinationHostname": "example.invalid",
                "Protocol": "tcp",
            }
        },
    }

    c = build_canonical_event(event)
    assert c["event"]["category"] == "network"
    assert c["event"]["action"] == "connection"
    assert c["network"]["source_ip"] == "10.0.0.10"
    assert c["network"]["source_port"] == 51515
    assert c["network"]["destination_ip"] == "203.0.113.8"
    assert c["network"]["destination_port"] == 443
    assert c["process"]["pid"] == 123


def test_security_4624_maps_session_and_authentication_context():
    event = {
        "event_id": 4624,
        "source": "Microsoft-Windows-Security-Auditing",
        "host": "DC01",
        "raw": {
            "event_data": {
                "TargetUserName": "bob",
                "TargetUserSid": "S-1-5-21-2",
                "TargetLogonId": "0xabc",
                "LogonType": "3",
                "AuthenticationPackageName": "NTLM",
                "IpAddress": "10.0.0.15",
                "IpPort": "49222",
            }
        },
    }

    c = build_canonical_event(event)
    assert c["event"]["category"] == "authentication"
    assert c["event"]["action"] == "logon_success"
    assert c["user"] == {"name": "bob", "id": "S-1-5-21-2"}
    assert c["session"]["id"] == "0xabc"
    assert c["authentication"]["logon_type"] == 3
    assert c["authentication"]["ip_address"] == "10.0.0.15"


def test_powershell_4104_maps_script_block():
    event = {
        "event_id": 4104,
        "source": "Microsoft-Windows-PowerShell",
        "raw": {
            "event_data": {
                "ScriptBlockText": "Get-Process | Select-Object Name",
                "Path": r"C:\Temp\test.ps1",
            }
        },
    }
    c = build_canonical_event(event)
    assert c["event"]["category"] == "script"
    assert c["event"]["action"] == "script_block"
    assert c["script"]["text"].startswith("Get-Process")
    assert c["script"]["path"].endswith("test.ps1")


def test_real_evtx_parser_path_attaches_canonical_without_breaking_legacy_fields():
    xml = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2026-09-01T01:02:03.0000000Z" />
        <Computer>WIN-A</Computer>
      </System>
      <EventData>
        <Data Name="SubjectUserName">alice</Data>
        <Data Name="SubjectLogonId">0x123</Data>
        <Data Name="NewProcessId">0x2000</Data>
        <Data Name="ProcessId">0x1000</Data>
        <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
        <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
        <Data Name="CommandLine">cmd.exe /c whoami</Data>
      </EventData>
    </Event>"""

    result = _extract_from_xml(xml)
    c = result["raw"]["canonical"]

    assert result["event_id"] in (4688, "4688")
    assert result["host"] == "WIN-A"
    assert "cmd.exe" in result["command_line"]
    assert c["event"]["provider"] == "windows.security"
    assert c["event"]["category"] == "process"
    assert c["event"]["action"] == "process_start"
    assert c["process"]["pid"] == 8192
    assert c["process"]["parent_pid"] == 4096
    assert c["session"]["id"] == "0x123"


def test_unknown_provider_event_is_preserved_as_unknown_observed_not_misclassified():
    event = {
        "event_id": 9999,
        "source": "Vendor-Custom-Provider",
        "host": "X",
        "raw": {"event_data": {"Something": "value"}},
    }
    c = build_canonical_event(event)
    assert c["event"]["provider"] == "Vendor-Custom-Provider"
    assert c["event"]["category"] == "unknown"
    assert c["event"]["action"] == "observed"
