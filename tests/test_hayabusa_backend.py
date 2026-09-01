from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from breachscope import hayabusa


def _alert_record(**overrides):
    record = {
        "Timestamp": "2026-09-01T01:02:03.0000000Z",
        "Computer": "WIN-A",
        "Channel": "Sysmon",
        "EventID": 1,
        "Level": "high",
        "RecordID": 42,
        "RuleTitle": "Suspicious PowerShell",
        "RuleID": "11111111-2222-3333-4444-555555555555",
        "Provider": "Microsoft-Windows-Sysmon",
        "MitreTags": ["T1059.001", "T1105"],
        "Details": {
            "CmdLine": "powershell.exe -enc AAAA",
            "User": "CORP\\alice",
            "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
    }
    record.update(overrides)
    return record


def test_hayabusa_record_maps_to_breachscope_finding_and_preserves_raw():
    record = _alert_record()
    finding = hayabusa.finding_from_hayabusa_record(record)

    assert finding is not None
    assert finding.rule_id == record["RuleID"]
    assert finding.rule_name == "Suspicious PowerShell"
    assert finding.severity == "high"
    assert finding.mitre_technique == "T1059.001"
    assert finding.event.host == "WIN-A"
    assert finding.event.event_id == "1"
    assert finding.event.user == "CORP\\alice"
    assert finding.event.command_line == "powershell.exe -enc AAAA"
    assert finding.event.raw["detection_backend"] == "hayabusa"
    assert finding.event.raw["hayabusa"] == record


def test_info_timeline_records_are_not_findings_by_default():
    assert hayabusa.finding_from_hayabusa_record(
        _alert_record(Level="info")
    ) is None


def test_info_records_can_be_explicitly_included_as_low():
    finding = hayabusa.finding_from_hayabusa_record(
        _alert_record(Level="info"),
        include_informational=True,
    )
    assert finding is not None
    assert finding.severity == "low"


def test_hayabusa_level_mapping():
    expected = {
        "crit": "critical",
        "high": "high",
        "med": "medium",
        "low": "low",
    }
    for level, severity in expected.items():
        finding = hayabusa.finding_from_hayabusa_record(
            _alert_record(Level=level)
        )
        assert finding is not None
        assert finding.severity == severity


def test_jsonl_parser_deduplicates_same_detection(tmp_path):
    record = _alert_record()
    output = tmp_path / "results.jsonl"
    payload = json.dumps(record) + "\n" + json.dumps(record) + "\n"
    output.write_text(payload, encoding="utf-8")

    findings = hayabusa.parse_hayabusa_jsonl(output)
    assert len(findings) == 1


def test_build_command_uses_official_dfir_timeline_jsonl_contract(tmp_path):
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"fake")
    exe = tmp_path / "hayabusa.exe"
    output = tmp_path / "out.jsonl"

    command = hayabusa.build_hayabusa_command(exe, evtx, output)

    assert command[1] == "dfir-timeline"
    assert ["-f", str(evtx)] == command[2:4]
    assert "-t" in command and command[command.index("-t") + 1] == "jsonl"
    assert "-o" in command and command[command.index("-o") + 1] == str(output)
    assert "-w" in command
    assert "-O" in command
    assert "-p" in command
    assert command[command.index("-p") + 1] == "super-verbose"


def test_directory_without_evtx_skips_optional_backend_before_binary_resolution(tmp_path, monkeypatch):
    def fail_resolve(*args, **kwargs):
        raise AssertionError("binary resolution should not occur without EVTX")

    monkeypatch.setattr(hayabusa, "resolve_hayabusa_executable", fail_resolve)
    assert hayabusa.run_hayabusa_findings(tmp_path) == []


def test_run_hayabusa_parses_backend_output(tmp_path, monkeypatch):
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"fake")
    exe = tmp_path / "hayabusa.exe"
    exe.write_bytes(b"fake")

    monkeypatch.setattr(
        hayabusa,
        "resolve_hayabusa_executable",
        lambda explicit=None: exe,
    )

    def fake_run(command, *, cwd, timeout):
        output = Path(command[command.index("-o") + 1])
        output.write_text(
            json.dumps(_alert_record()) + "\n",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(hayabusa, "_run_command", fake_run)

    findings = hayabusa.run_hayabusa_findings(tmp_path)
    assert len(findings) == 1
    assert findings[0].event.raw["detection_backend"] == "hayabusa"


def test_backend_failure_is_explicit_not_silently_ignored(tmp_path, monkeypatch):
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"fake")
    exe = tmp_path / "hayabusa.exe"
    exe.write_bytes(b"fake")

    monkeypatch.setattr(
        hayabusa,
        "resolve_hayabusa_executable",
        lambda explicit=None: exe,
    )
    monkeypatch.setattr(
        hayabusa,
        "_run_command",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=7,
            stdout="",
            stderr="backend failed",
        ),
    )

    with pytest.raises(hayabusa.HayabusaError, match="backend failed"):
        hayabusa.run_hayabusa_findings(tmp_path)


def test_p0_10_marker_in_pipeline():
    import breachscope.pipeline as pipeline

    source = open(pipeline.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P0_10_HAYABUSA_BACKEND_V1" in source
