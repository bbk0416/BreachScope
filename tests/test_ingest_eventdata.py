from __future__ import annotations

from breachscope.ingest import _extract_from_xml


WINDOWS_EVENT_XML = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-01T01:02:03.4567890Z" />
    <EventRecordID>12345</EventRecordID>
    <Execution ProcessID="4" ThreadID="100" />
    <Channel>Security</Channel>
    <Computer>WORKSTATION01.example.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-111-222-333-1001</Data>
    <Data Name="SubjectUserName">analyst</Data>
    <Data Name="SubjectLogonId">0x123abc</Data>
    <Data Name="NewProcessId">0x2345</Data>
    <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ProcessId">0x1111</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile -EncodedCommand SQBFAFgA</Data>
  </EventData>
</Event>"""


def test_extract_from_xml_preserves_all_named_eventdata_in_raw():
    result = _extract_from_xml(WINDOWS_EVENT_XML)
    raw = result["raw"]

    assert raw["SubjectUserSid"] == "S-1-5-21-111-222-333-1001"
    assert raw["SubjectUserName"] == "analyst"
    assert raw["SubjectLogonId"] == "0x123abc"
    assert raw["NewProcessId"] == "0x2345"
    assert raw["NewProcessName"].endswith("powershell.exe")
    assert raw["ProcessId"] == "0x1111"
    assert raw["ParentProcessName"].endswith("explorer.exe")
    assert raw["CommandLine"].startswith("powershell.exe")
    assert raw["event_data"]["SubjectLogonId"] == "0x123abc"
    assert raw["event_data"]["ParentProcessName"].endswith("explorer.exe")
    assert len(raw["event_data_records"]) == 8


def test_extract_from_xml_preserves_system_metadata_without_breaking_legacy_fields():
    result = _extract_from_xml(WINDOWS_EVENT_XML)
    raw = result["raw"]
    system = raw["system"]

    assert system["ProviderName"] == "Microsoft-Windows-Security-Auditing"
    assert system["EventID"] == "4688"
    assert system["Channel"] == "Security"
    assert system["Computer"] == "WORKSTATION01.example.local"
    assert system["SystemTime"] == "2026-09-01T01:02:03.4567890Z"
    assert system["ExecutionProcessID"] == "4"
    assert system["ExecutionThreadID"] == "100"
    assert system["SecurityUserID"] == "S-1-5-18"

    assert result.get("event_id") in (4688, "4688")
    assert result.get("host") == "WORKSTATION01.example.local"
    assert "powershell.exe" in (result.get("command_line") or "")


def test_extract_from_xml_does_not_silently_overwrite_duplicate_or_unnamed_eventdata():
    xml = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>1</EventID><Computer>host</Computer></System>
      <EventData>
        <Data Name="Repeated">one</Data>
        <Data Name="Repeated">two</Data>
        <Data>unnamed-one</Data>
        <Data>unnamed-two</Data>
      </EventData>
    </Event>"""
    result = _extract_from_xml(xml)
    raw = result["raw"]

    assert raw["Repeated"] == ["one", "two"]
    assert raw["event_data"]["Repeated"] == ["one", "two"]
    assert raw["event_data_unnamed"] == ["unnamed-one", "unnamed-two"]
    assert len(raw["event_data_records"]) == 4


def test_extract_from_xml_preserves_provider_specific_userdata():
    xml = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>999</EventID><Computer>host</Computer></System>
      <UserData>
        <CustomPayload xmlns="urn:vendor:test" Foo="bar">
          <Nested>evidence</Nested>
        </CustomPayload>
      </UserData>
    </Event>"""
    result = _extract_from_xml(xml)
    user_data = result["raw"]["user_data"]

    assert user_data[0]["tag"] == "UserData"
    assert user_data[0]["children"][0]["tag"] == "CustomPayload"
    assert user_data[0]["children"][0]["attributes"]["Foo"] == "bar"
    assert user_data[0]["children"][0]["children"][0]["text"] == "evidence"
