from __future__ import annotations

from datetime import datetime, timedelta, timezone

from breachscope.correlator import correlate_events
from breachscope.schemas import Event, Finding


def _event(*, ts, host, event_id, user="", command_line="", raw=None, source="test"):
    return Event(
        timestamp=ts.isoformat(),
        host=host,
        source=source,
        event_id=str(event_id),
        user=user,
        command_line=command_line,
        raw=raw or {},
    )


def _finding(event: Event, technique: str = "T1569.002") -> Finding:
    return Finding(
        rule_id="R-LATERAL",
        rule_name="Remote execution",
        severity="high",
        mitre_technique=technique,
        event=event,
        matched_value=event.command_line or str(event.event_id),
    )

def _remote(chains):
    return [chain for chain in chains if chain.chain_type == "remote_execution"]


def test_psexec_plus_target_network_logon_and_service_forms_cross_host_chain():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts,
        host="WS-A.corp.local",
        event_id=1,
        user=r"CORP\alice",
        command_line=r"psexec.exe \\WS-B -u CORP\alice cmd.exe /c whoami",
    )
    logon = _event(
        ts=ts + timedelta(seconds=2),
        host="WS-B.corp.local",
        event_id=4624,
        user="alice",
        raw={"LogonType": "3", "TargetUserName": "alice", "IpAddress": "10.0.0.10"},
    )
    service = _event(
        ts=ts + timedelta(seconds=20),
        host="WS-B.corp.local",
        event_id=7045,
        raw={"ServiceName": "PSEXESVC"},
    )
    chains = _remote(correlate_events([source, logon, service], [_finding(source)]))
    assert len(chains) == 1
    chain = chains[0]
    assert chain.events == [source, logon, service]
    assert {event.host for event in chain.events} == {"WS-A.corp.local", "WS-B.corp.local"}
    assert chain.findings == [_finding(source)]
    assert chain.metadata["remote_execution"] == {
        "source_host": "WS-A.corp.local",
        "target_host": "WS-B.corp.local",
        "method": "psexec",
    }


def test_powershell_scriptblock_computername_links_to_target_network_logon():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts,
        host="WS-A.corp.local",
        event_id=4104,
        raw={"ScriptBlockText": "Invoke-Command -ComputerName WS-B -ScriptBlock { hostname }"},
    )
    logon = _event(
        ts=ts + timedelta(seconds=5),
        host="WS-B.corp.local",
        event_id=4624,
        user="alice",
        raw={"LogonType": 3, "TargetUserName": "alice", "IpAddress": "10.0.0.10"},
    )

    winrm = _event(
        ts=ts + timedelta(seconds=6),
        host="WS-B.corp.local",
        event_id=1,
        user=r"CORP\alice",
        command_line=r"C:\Windows\System32\wsmprovhost.exe -Embedding",
    )
    chains = _remote(correlate_events([source, logon, winrm], []))

    assert len(chains) == 1
    assert chains[0].metadata["remote_execution"] == {
        "source_host": "WS-A.corp.local",
        "target_host": "WS-B.corp.local",
        "method": "powershell",
    }
    assert chains[0].events == [source, logon, winrm]


def test_remote_target_without_target_side_evidence_does_not_form_chain():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts,
        host="WS-A",
        event_id=1,
        user="alice",
        command_line=r"psexec \\WS-B cmd.exe",
    )
    unrelated = _event(
        ts=ts + timedelta(seconds=10),
        host="WS-B",
        event_id=4688,
        user="alice",
        command_line="notepad.exe",
    )

    assert _remote(correlate_events([source, unrelated], [_finding(source)])) == []


def test_target_logon_user_mismatch_does_not_form_chain():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts,
        host="WS-A",
        event_id=1,
        user=r"CORP\alice",
        command_line=r"psexec \\WS-B cmd.exe",
    )
    logon = _event(
        ts=ts + timedelta(seconds=3),
        host="WS-B",
        event_id=4624,
        user="bob",
        raw={"LogonType": 3, "TargetUserName": "bob", "IpAddress": "10.0.0.10"},
    )
    assert _remote(correlate_events([source, logon], [_finding(source)])) == []


def test_remote_logon_outside_two_minute_window_does_not_form_chain():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts,
        host="WS-A",
        event_id=4104,
        raw={"ScriptBlockText": "Enter-PSSession -ComputerName WS-B"},
    )
    logon = _event(
        ts=ts + timedelta(minutes=2, seconds=1),
        host="WS-B",
        event_id=4624,
        raw={"LogonType": 3, "TargetUserName": "alice", "IpAddress": "10.0.0.10"},
    )

    assert _remote(correlate_events([source, logon], [])) == []


def test_plain_unc_file_copy_does_not_form_lateral_chain():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts,
        host="WS-A",
        event_id=1,
        user="alice",
        command_line=r"copy C:\Temp\a.txt \\WS-B\share\a.txt",
    )
    logon = _event(
        ts=ts + timedelta(seconds=3),
        host="WS-B",
        event_id=4624,
        user="alice",
        raw={"LogonType": 3, "TargetUserName": "alice", "IpAddress": "10.0.0.10"},
    )
    assert _remote(correlate_events([source, logon], [_finding(source)])) == []



def test_psexec_generic_service_name_is_not_remote_execution_evidence():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts, host="WS-A", event_id=1, user="alice",
        command_line=r"psexec \\WS-B cmd.exe",
    )
    logon = _event(
        ts=ts + timedelta(seconds=2), host="WS-B", event_id=4624, user="alice",
        raw={"LogonType": 3, "TargetUserName": "alice"},
    )
    service = _event(
        ts=ts + timedelta(seconds=10), host="WS-B", event_id=7045,
        raw={"ServiceName": "UnrelatedService"},
    )
    assert _remote(correlate_events([source, logon, service], [_finding(source)])) == []


def test_custom_invoke_function_with_computername_is_not_winrm():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts, host="WS-A", event_id=4104,
        raw={"ScriptBlockText": "Invoke-SeaDukeStage -ComputerName WS-B"},
    )
    logon = _event(
        ts=ts + timedelta(seconds=1), host="WS-B", event_id=4624,
        raw={"LogonType": 3, "TargetUserName": "alice"},
    )
    winrm = _event(
        ts=ts + timedelta(seconds=2), host="WS-B", event_id=1, user="alice",
        command_line=r"C:\Windows\System32\wsmprovhost.exe -Embedding",
    )
    assert _remote(correlate_events([source, logon, winrm], [])) == []


def test_winrm_allows_small_target_timestamp_skew():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts, host="WS-A", event_id=4104,
        raw={"ScriptBlockText": "Invoke-Command -ComputerName WS-B { hostname }"},
    )
    logon = _event(
        ts=ts - timedelta(milliseconds=10), host="WS-B", event_id=4624, user="alice",
        raw={"LogonType": 3, "TargetUserName": "alice"},
    )
    winrm = _event(
        ts=ts - timedelta(milliseconds=5), host="WS-B", event_id=4688, user="alice",
        command_line=r"C:\Windows\System32\wsmprovhost.exe -Embedding",
    )
    chains = _remote(correlate_events([logon, winrm, source], []))
    assert len(chains) == 1
    assert {event.host for event in chains[0].events} == {"WS-A", "WS-B"}


def test_remote_logon_prefers_target_username_over_subject_placeholder():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts, host="WS-A", event_id=1, user=r"CORP\alice",
        command_line=r"psexec \\WS-B cmd.exe",
    )
    logon = _event(
        ts=ts + timedelta(seconds=2), host="WS-B", event_id=4624, user="-",
        raw={"LogonType": 3, "SubjectUserName": "-", "TargetUserName": "alice"},
    )
    service = _event(
        ts=ts + timedelta(seconds=10), host="WS-B", event_id=7045,
        raw={"ServiceName": "PSEXESVC"},
    )
    chains = _remote(correlate_events([source, logon, service], [_finding(source)]))
    assert len(chains) == 1
    assert chains[0].events == [source, logon, service]


def test_duplicate_source_telemetry_for_same_remote_operation_is_collapsed():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    sysmon = _event(ts=ts, host="WS-A", event_id=1, user="alice", command_line=r"psexec \\WS-B cmd.exe")
    security = _event(ts=ts + timedelta(seconds=1), host="WS-A", event_id=4688, user="alice", command_line=r"psexec \\WS-B cmd.exe")
    logon = _event(
        ts=ts + timedelta(seconds=2), host="WS-B", event_id=4624, user="-",
        raw={"LogonType": 3, "TargetUserName": "alice"},
    )
    service = _event(
        ts=ts + timedelta(seconds=10), host="WS-B", event_id=7045,
        raw={"ServiceName": "PSEXESVC"},
    )
    chains = _remote(correlate_events([sysmon, security, logon, service], [_finding(sysmon), _finding(security)]))
    assert len(chains) == 1
    assert sysmon in chains[0].events
    assert security not in chains[0].events


def test_winrm_requires_target_wsmprovhost_process():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts, host="WS-A", event_id=4104,
        raw={"ScriptBlockText": "Invoke-Command -ComputerName WS-B { hostname }"},
    )
    logon = _event(
        ts=ts + timedelta(seconds=1), host="WS-B", event_id=4624, user="alice",
        raw={"LogonType": 3, "TargetUserName": "alice"},
    )
    assert _remote(correlate_events([source, logon], [])) == []


def test_winrm_rejects_target_evidence_before_backward_skew_window():
    ts = datetime(2026, 9, 17, tzinfo=timezone.utc)
    source = _event(
        ts=ts, host="WS-A", event_id=4104,
        raw={"ScriptBlockText": "Invoke-Command -ComputerName WS-B { hostname }"},
    )
    logon = _event(
        ts=ts - timedelta(seconds=6), host="WS-B", event_id=4624, user="alice",
        raw={"LogonType": 3, "TargetUserName": "alice"},
    )
    winrm = _event(
        ts=ts - timedelta(seconds=6), host="WS-B", event_id=4688, user="alice",
        command_line=r"C:\Windows\System32\wsmprovhost.exe -Embedding",
    )
    assert _remote(correlate_events([logon, winrm, source], [])) == []


def test_remote_chain_cannot_bridge_generic_scenario_components(monkeypatch):
    import breachscope.scenario as scenario_module

    class _Chain:
        def __init__(self, chain_type):
            self.chain_type = chain_type

    captured = []

    def _capture(chains):
        captured.extend(chains)
        return []

    monkeypatch.setattr(scenario_module, "_bs_p005_partition_chains", _capture)
    result = scenario_module.infer_scenarios(
        [_Chain("remote_execution"), _Chain("activity")], []
    )

    assert result == []
    assert [chain.chain_type for chain in captured] == ["activity"]
