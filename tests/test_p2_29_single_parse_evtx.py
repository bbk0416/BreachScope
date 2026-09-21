from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

import breachscope.ingest as ingest


ROOT = Path(__file__).resolve().parents[1]
MAINTENANCE = ROOT / "external_baseline" / "p2_29_single_parse_parser_maintenance.yaml"


EVENT_DATA_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{11111111-1111-1111-1111-111111111111}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-21T01:02:03.0000000Z"/>
    <EventRecordID>42</EventRecordID>
    <Execution ProcessID="123" ThreadID="456"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>host.example</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="SubjectUserName">tester</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd-copy.exe</Data>
    <Data>unnamed-value</Data>
  </EventData>
</Event>"""


USER_DATA_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog"/>
    <EventID>104</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-09-21T01:02:03.0000000Z"/>
    <EventRecordID>99</EventRecordID>
    <Channel>System</Channel>
    <Computer>host.example</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>operator</SubjectUserName>
      <SubjectDomainName>EXAMPLE</SubjectDomainName>
      <Channel>System</Channel>
    </LogFileCleared>
  </UserData>
</Event>"""


def _prior_two_parse_composition(xml_text: str) -> dict:
    result = ingest._extract_legacy_event_fields(xml_text)
    extracted = ingest._bs_extract_evtx_raw(xml_text)
    existing = result.get("raw")

    if not isinstance(existing, dict):
        result["raw"] = extracted
    else:
        merged = dict(existing)
        for key, value in extracted.items():
            if key not in merged:
                merged[key] = value
            elif (
                key in ("event_data", "system")
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                combined = dict(value)
                combined.update(merged[key])
                merged[key] = combined
        result["raw"] = merged

    return ingest._bs_enrich_canonical_event(result)


@pytest.mark.parametrize("xml_text", [EVENT_DATA_XML, USER_DATA_XML])
def test_p2_29_single_parse_output_matches_prior_two_parse_composition(
    xml_text: str,
) -> None:
    assert ingest._extract_from_xml(xml_text) == _prior_two_parse_composition(xml_text)


def test_p2_29_canonical_parser_calls_elementtree_fromstring_once(monkeypatch) -> None:
    real_fromstring = ET.fromstring
    calls = 0

    def counting_fromstring(text):
        nonlocal calls
        calls += 1
        return real_fromstring(text)

    monkeypatch.setattr(ET, "fromstring", counting_fromstring)

    row = ingest._extract_from_xml(EVENT_DATA_XML)

    assert row["event_id"] == "1"
    assert calls == 1


def test_p2_29_independent_legacy_and_raw_helpers_keep_existing_behavior() -> None:
    legacy = ingest._extract_legacy_event_fields(EVENT_DATA_XML)
    raw = ingest._bs_extract_evtx_raw(EVENT_DATA_XML)

    assert legacy["event_id"] == "1"
    assert legacy["user"] == "tester"
    assert legacy["command_line"] == "cmd.exe /c whoami"
    assert raw["event_data"]["SubjectUserName"] == "tester"
    assert raw["event_data"]["Image"] == [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\cmd-copy.exe",
    ]
    assert raw["event_data_unnamed"] == ["unnamed-value"]
    assert raw["system"]["EventRecordID"] == "42"


def test_p2_29_malformed_xml_still_fails_closed_in_canonical_parser() -> None:
    with pytest.raises(ET.ParseError):
        ingest._extract_from_xml("<Event><System><EventID>1</EventID>")


def test_p2_29_legacy_helper_still_returns_empty_mapping_for_malformed_xml() -> None:
    assert ingest._extract_legacy_event_fields("<Event>") == {}


def test_p2_29_maintenance_record_preserves_current_detection_evidence_sources() -> None:
    row = yaml.safe_load(MAINTENANCE.read_text(encoding="utf-8"))
    assert row["status"] == "COMPATIBILITY_PROVEN_ON_CURRENT_SEALED_EVIDENCE_SOURCES"
    assert row["parser"]["historical_p2_20_git_blob_sha1"] == (
        "42ce35bff10d0541d26e0a5181cfcd1ef9a459cc"
    )
    assert row["parser"]["current_git_blob_sha1"] == (
        "34534bf8256ce658c5f05991c05045f7c5066816"
    )

    p25 = row["equivalence"]["p2_25"]
    assert p25["exact_evtx_files"] == 8
    assert p25["records_compared"] == 450
    assert p25["mismatches"] == 0
    assert p25["all_normalized_dicts_equal"] is True
    assert p25["old_aggregate_digest_sha256"] == p25["new_aggregate_digest_sha256"]

    p26c = row["equivalence"]["p2_26c"]
    assert p26c["exact_evtx_files"] == 5
    assert p26c["records_compared"] == 1643
    assert p26c["mismatches"] == 0
    assert p26c["all_normalized_dicts_equal"] is True
    assert p26c["old_aggregate_digest_sha256"] == p26c["new_aggregate_digest_sha256"]

    combined = row["equivalence"]["combined_current_revalidation_sources"]
    assert combined["exact_evtx_files"] == 13
    assert combined["records_compared"] == 2093
    assert combined["mismatches"] == 0
    assert combined["all_normalized_dicts_equal"] is True
    assert combined["old_aggregate_digest_sha256"] == (
        "a22fb6b0cb9faed59ab2813629e6dea7625ccad7519c512d0b99e9587d7ec8d9"
    )
    assert combined["old_aggregate_digest_sha256"] == combined["new_aggregate_digest_sha256"]

    claim = row["claim_boundary"]
    assert claim["speedup"] == "NOT_YET_FORMALLY_MEASURED"
    assert claim["production_capacity"] == "NOT_CLAIMED"
    assert claim["new_detection_accuracy_measurement"] is False
