from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

from breachscope.ingest import convert_evtx_dir

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_external_holdout.py"
SPEC = importlib.util.spec_from_file_location("external_holdout_p205d", SCRIPT)
assert SPEC and SPEC.loader
holdout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(holdout)


class _FakeRecord:
    def xml(self) -> str:
        return """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog"/>
    <EventID>104</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-01-01T00:00:00.0000000Z"/>
    <EventRecordID>42</EventRecordID>
    <Channel>System</Channel>
    <Computer>host.example</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>tester</SubjectUserName>
      <SubjectDomainName>EXAMPLE</SubjectDomainName>
      <Channel>System</Channel>
      <BackupPath/>
    </LogFileCleared>
  </UserData>
</Event>"""


class _FakeEvtx:
    seen_filename = None

    def __init__(self, filename):
        if not isinstance(filename, (str, bytes, os.PathLike)):
            raise TypeError(
                f"expected str, bytes or os.PathLike object, not {type(filename).__name__}"
            )
        type(self).seen_filename = filename

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def records(self):
        return [_FakeRecord()]


def _base_event(record_id: str | None = None, channel: str = "System") -> dict:
    raw = {}
    if record_id is not None:
        raw["system"] = {
            "EventRecordID": record_id,
            "Channel": channel,
        }
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "WS-01",
        "source": "Microsoft-Windows-Eventlog",
        "event_id": "104",
        "user": "",
        "command_line": "",
        "raw": raw,
    }


def test_convert_evtx_dir_passes_path_to_python_evtx(monkeypatch, tmp_path: Path) -> None:
    evtx_file = tmp_path / "sample.evtx"
    evtx_file.write_bytes(b"fixture")

    evtx_module = importlib.import_module("Evtx.Evtx")
    monkeypatch.setattr(evtx_module, "Evtx", _FakeEvtx)

    converted = convert_evtx_dir(tmp_path)

    assert converted is not None
    assert isinstance(_FakeEvtx.seen_filename, (str, bytes, os.PathLike))
    assert Path(_FakeEvtx.seen_filename) == evtx_file

    output = converted / "sample.jsonl"
    rows = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 1
    assert str(rows[0]["event_id"]) == "104"
    assert rows[0]["raw"]["system"]["EventRecordID"] == "42"


def test_event_key_uses_event_record_id_when_available() -> None:
    assert holdout.event_key(_base_event("5073")) != holdout.event_key(_base_event("5074"))


def test_event_key_scopes_event_record_id_by_channel() -> None:
    assert holdout.event_key(_base_event("100", "System")) != holdout.event_key(
        _base_event("100", "Security")
    )


def test_event_key_keeps_fail_closed_behavior_without_discriminator(tmp_path: Path) -> None:
    corpus = tmp_path / "events.jsonl"
    event = _base_event()
    corpus.write_text(
        json.dumps(event) + "\n" + json.dumps(event) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema": holdout.SCHEMA,
        "kind": "external_blind_holdout",
        "evaluation_class": "external_calibration",
        "protocol": {
            "independent_from_rule_authoring": False,
            "ground_truth_prepared_without_breachscope_findings": True,
            "final_holdout_seen_before_rule_freeze": True,
        },
        "provenance": {
            "source": "unit-test fixture",
            "license_or_permission": "test fixture",
        },
        "files": [
            {
                "path": corpus.name,
                "sha256": __import__("hashlib").sha256(corpus.read_bytes()).hexdigest(),
                "format": "jsonl",
            }
        ],
    }
    manifest_path = tmp_path / "manifest.yaml"
    import yaml

    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(holdout.HoldoutError, match="duplicate event identity"):
        holdout.load_corpus_records(
            holdout.load_manifest(manifest_path),
            tmp_path,
        )
