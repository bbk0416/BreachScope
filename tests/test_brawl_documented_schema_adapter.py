from breachscope.brawl import (
    BrawlAdapterError,
    event_from_brawl_record,
    event_from_brawl_sysmon,
    event_from_brawl_win_event,
    extract_bsf_steps,
)


def test_brawl_sysmon_process_create_documented_schema():
    record = {
        "@timestamp": "2017-02-22T18:38:14.060000Z",
        "@uuid": "sysmon-1",
        "type": "sysmon",
        "game_id": "game-1",
        "host": "beane-pc.brawlco.com",
        "data_model": {
            "object": "process",
            "action": ["create"],
            "fields": {
                "utc_time": "2017-02-22T18:38:13.999000Z",
                "command_line": "powershell.exe -nop -enc AAAA",
                "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_image_path": "C:\\Windows\\explorer.exe",
                "pid": 4321,
                "ppid": 1234,
                "user": "BRAWLCO\\beane",
                "sha256_hash": "abc123",
            },
        },
    }

    event = event_from_brawl_sysmon(record)

    assert event.timestamp == "2017-02-22T18:38:13.999000Z"
    assert event.raw["brawl_adapter"]["timestamp_source"] == "data_model.fields.utc_time"
    assert event.host == "beane-pc.brawlco.com"
    assert event.source == "Microsoft-Windows-Sysmon"
    assert event.event_id == "1"
    assert event.command_line == "powershell.exe -nop -enc AAAA"
    assert event.user == "BRAWLCO\\beane"
    assert event.raw["event_data"]["Image"].endswith("powershell.exe")
    assert event.raw["event_data"]["ParentImage"].endswith("explorer.exe")
    assert event.raw["event_data"]["Hashes"] == "SHA256=abc123"
    assert event.raw["canonical"]["event"]["provider"] == "windows.sysmon"
    assert event.raw["canonical"]["event"]["category"] == "process"
    assert event.raw["canonical"]["event"]["action"] == "process_start"
    assert event.raw["canonical"]["process"]["pid"] == 4321
    assert event.raw["canonical"]["process"]["parent_pid"] == 1234


def test_brawl_win_event_documented_schema_uses_raw_windows_xml():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4688</EventID>
        <Level>0</Level>
        <TimeCreated SystemTime="2017-02-22T18:39:00.0000000Z" />
        <Computer>dc.brawlco.com</Computer>
      </System>
      <EventData>
        <Data Name="SubjectUserName">administrator</Data>
        <Data Name="NewProcessId">0x1234</Data>
        <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
        <Data Name="CommandLine">cmd.exe /c whoami</Data>
      </EventData>
    </Event>"""
    record = {
        "@timestamp": "2017-02-22T18:39:00.100000Z",
        "@uuid": "win-event-1",
        "type": "win_event",
        "game_id": "game-1",
        "host": "dc.brawlco.com",
        "raw": xml,
        "data_model": {"fields": {"log_name": "Security", "log_type": "Audit Success"}},
    }

    event = event_from_brawl_win_event(record)

    assert event.host == "dc.brawlco.com"
    assert event.source == "Microsoft-Windows-Security-Auditing"
    assert event.event_id == "4688"
    assert event.command_line == "cmd.exe /c whoami"
    assert event.raw["canonical"]["event"]["provider"] == "windows.security"
    assert event.raw["canonical"]["process"]["executable"].endswith("cmd.exe")
    assert event.raw["brawl_record"]["game_id"] == "game-1"


def test_brawl_record_dispatch_ignores_non_host_records():
    assert event_from_brawl_record({"type": "bsf_events", "bsf": []}) is None
    assert event_from_brawl_record({"type": "game_metadata"}) is None


def test_brawl_win_event_requires_raw_xml():
    try:
        event_from_brawl_win_event({"type": "win_event", "host": "host"})
    except BrawlAdapterError as exc:
        assert "raw Windows Event XML" in str(exc)
    else:
        raise AssertionError("expected BrawlAdapterError")


def test_bsf_steps_preserve_red_bot_attack_oracle_without_event_labels():
    record = {
        "type": "bsf_events",
        "producer_id": "caldera-red",
        "bsf": [
            {
                "id": "event-1",
                "nodetype": "event",
                "host": "dc.brawlco.com",
                "object": "process",
                "action": "create",
                "happened_after": "2017-02-22T18:38:14.000000Z",
                "happened_before": "2017-02-22T18:38:15.000000Z",
                "command_line": "powershell.exe -nop",
            },
            {
                "id": "step-1",
                "nodetype": "step",
                "events": ["event-1"],
                "attack_info": [
                    {
                        "technique_id": "T1086",
                        "technique_name": "PowerShell",
                        "tactic": ["Execution"],
                    }
                ],
            },
        ],
    }

    steps = extract_bsf_steps(record)

    assert steps == [
        {
            "step_id": "step-1",
            "techniques": [
                {
                    "technique_id": "T1086",
                    "technique_name": "PowerShell",
                    "tactic": ["Execution"],
                }
            ],
            "event_ids": ["event-1"],
            "events": [record["bsf"][0]],
        }
    ]
    assert "label" not in steps[0]